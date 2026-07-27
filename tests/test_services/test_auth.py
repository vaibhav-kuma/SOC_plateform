import pytest
from unittest.mock import MagicMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.auth_service.main import app
from core.database import get_session
from core.security import hash_password


@pytest.fixture(autouse=True)
def override_session(mock_db_session):
    app.router.lifespan_context = None
    async def _get_session():
        yield mock_db_session
    app.dependency_overrides[get_session] = _get_session
    yield
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def _setup_mock_user(mock_db_session):
    user = MagicMock()
    user.id = uuid4()
    user.email = "admin@socplatform.io"
    user.password_hash = hash_password("Admin123!")
    user.is_active = True
    user.mfa_enabled = False
    user.mfa_secret = None
    user.role = "admin"
    user.org_id = uuid4()
    user.permissions = ["*"]
    user.last_login = None
    user.full_name = "Admin User"

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db_session.execute.return_value = mock_result


@pytest.fixture
def _setup_disabled_user(mock_db_session):
    user = MagicMock()
    user.id = uuid4()
    user.email = "disabled@socplatform.io"
    user.password_hash = hash_password("AnyPass123!")
    user.is_active = False
    user.mfa_enabled = False
    user.last_login = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db_session.execute.return_value = mock_result


@pytest.mark.asyncio
async def test_login_success(_setup_mock_user):
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@socplatform.io", "password": "Admin123!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
        assert data["mfa_required"] is False


@pytest.mark.asyncio
async def test_login_invalid_password(mock_db_session):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@socplatform.io", "password": "WrongPass!"},
        )
        assert resp.status_code == 401
        data = resp.json()
        assert "detail" in data


@pytest.mark.asyncio
async def test_login_disabled_account(_setup_disabled_user):
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "disabled@socplatform.io", "password": "AnyPass123!"},
        )
        assert resp.status_code == 401
        data = resp.json()
        assert "detail" in data


@pytest.mark.asyncio
async def test_login_missing_fields():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/login", json={})
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_invalid_email():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "not-an-email", "password": "SomePass123!"},
        )
        assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_me_unauthorized():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_get_me_with_token(mock_db_session, auth_headers):
    from core.dependencies import get_current_user

    user = MagicMock()
    user.id = uuid4()
    user.email = "admin@socplatform.io"
    user.full_name = "Admin User"
    user.role = "admin"
    user.permissions = ["*"]
    user.mfa_enabled = False
    user.is_active = True
    user.last_login = None
    from datetime import datetime, timezone
    user.created_at = datetime.now(timezone.utc)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db_session.execute.return_value = mock_result

    async def _get_session():
        yield mock_db_session

    async def _get_current_user():
        return {
            "sub": str(user.id),
            "org_id": str(uuid4()),
            "role": "admin",
            "permissions": ["*"],
            "type": "access",
        }

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[get_current_user] = _get_current_user

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "admin@socplatform.io"

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_session, None)


@pytest.mark.asyncio
async def test_change_password(mock_db_session, auth_headers):
    from core.dependencies import get_current_user

    user = MagicMock()
    user.id = uuid4()
    user.email = "admin@socplatform.io"
    user.password_hash = hash_password("OldPass123!")
    user.full_name = "Admin User"
    user.role = "admin"
    user.permissions = ["*"]
    user.mfa_enabled = False
    user.is_active = True
    user.last_login = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db_session.execute.return_value = mock_result

    async def _get_session():
        yield mock_db_session

    async def _get_current_user():
        return {
            "sub": str(user.id),
            "org_id": str(uuid4()),
            "role": "admin",
            "permissions": ["*"],
            "type": "access",
        }

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[get_current_user] = _get_current_user

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={"current_password": "OldPass123!", "new_password": "NewPass456789!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "Password changed" in data["message"]

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_session, None)


@pytest.mark.asyncio
async def test_change_password_wrong_current(mock_db_session, auth_headers):
    from core.dependencies import get_current_user

    user = MagicMock()
    user.id = uuid4()
    user.email = "admin@socplatform.io"
    user.password_hash = hash_password("ActualPass123!")
    user.is_active = True

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db_session.execute.return_value = mock_result

    async def _get_session():
        yield mock_db_session

    async def _get_current_user():
        return {
            "sub": str(user.id),
            "org_id": str(uuid4()),
            "role": "admin",
            "permissions": ["*"],
            "type": "access",
        }

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[get_current_user] = _get_current_user

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={"current_password": "WrongOldPass!", "new_password": "NewPass456789!"},
        )
        assert resp.status_code == 401

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_session, None)


@pytest.mark.asyncio
async def test_change_password_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "OldPass123!", "new_password": "NewPass456789!"},
        )
        assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_refresh_token(mock_db_session):
    from datetime import datetime, timezone, timedelta
    from core.security import create_refresh_token
    from services.auth_service.models.domain import RefreshToken

    user_id = uuid4()
    refresh = create_refresh_token({"sub": str(user_id)})

    stored = MagicMock(spec=RefreshToken)
    stored.token_hash = ""
    stored.is_revoked = False
    stored.expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    stored.user_id = user_id

    user = MagicMock()
    user.id = user_id
    user.email = "admin@socplatform.io"
    user.org_id = uuid4()
    user.role = "admin"
    user.permissions = ["*"]
    user.is_active = True
    user.mfa_enabled = False
    user.mfa_secret = None
    user.last_login = None
    user.full_name = "Admin User"
    user.password_hash = ""

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.side_effect = [stored, user]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data


@pytest.mark.asyncio
async def test_logout(mock_db_session, auth_headers):
    from core.dependencies import get_current_user
    from core.security import create_refresh_token

    refresh = create_refresh_token({"sub": str(uuid4())})

    async def _get_session():
        yield mock_db_session

    async def _get_current_user():
        return {
            "sub": str(uuid4()),
            "org_id": str(uuid4()),
            "role": "admin",
            "permissions": ["*"],
            "type": "access",
        }

    app.dependency_overrides[get_session] = _get_session
    app.dependency_overrides[get_current_user] = _get_current_user

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/logout",
            headers=auth_headers,
            json={"refresh_token": refresh},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "Logged out" in data["message"]

    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_session, None)
