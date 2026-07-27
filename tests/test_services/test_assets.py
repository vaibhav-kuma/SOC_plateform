import pytest
from unittest.mock import MagicMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.asset_discovery.main import app
from core.database import get_session
from core.dependencies import get_current_user


@pytest.fixture(autouse=True)
def override_deps(mock_db_session):
    app.router.lifespan_context = None
    async def _get_session():
        yield mock_db_session
    app.dependency_overrides[get_session] = _get_session
    yield
    app.dependency_overrides.pop(get_session, None)


@pytest.fixture
def auth_override():
    user_data = {
        "sub": str(uuid4()),
        "org_id": str(uuid4()),
        "role": "admin",
        "permissions": ["*"],
        "type": "access",
    }
    async def _get_current_user():
        return user_data
    app.dependency_overrides[get_current_user] = _get_current_user
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_list_assets_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assets")
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_assets(mock_db_session, auth_override):
    asset = MagicMock()
    asset.id = uuid4()
    asset.hostname = "web-server-01"
    asset.ip_address = "192.168.1.100"
    asset.mac_address = "00:11:22:33:44:55"
    asset.os = "Linux"
    asset.os_version = "Ubuntu 22.04"
    asset.asset_type = "server"
    asset.risk_score = 7.5
    asset.tags = ["web", "production"]
    asset.first_seen = None
    asset.last_seen = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [asset]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assets")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["hostname"] == "web-server-01"
        assert data[0]["asset_type"] == "server"


@pytest.mark.asyncio
async def test_get_asset(mock_db_session, auth_override):
    asset_id = uuid4()
    asset = MagicMock()
    asset.id = asset_id
    asset.hostname = "db-primary"
    asset.ip_address = "192.168.1.50"
    asset.mac_address = None
    asset.os = "Linux"
    asset.os_version = "Debian 12"
    asset.asset_type = "database"
    asset.risk_score = 9.2
    asset.tags = ["db", "critical"]
    asset.attributes = {"role": "primary"}
    asset.first_seen = None
    asset.last_seen = None
    asset.created_at = None
    asset.updated_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = asset
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/assets/{asset_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hostname"] == "db-primary"
        assert data["asset_type"] == "database"


@pytest.mark.asyncio
async def test_get_asset_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/assets/{uuid4()}")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_asset_stats(mock_db_session, auth_override):
    asset = MagicMock()
    asset.asset_type = "server"
    asset.risk_score = 7.5
    asset.created_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [asset]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assets/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_assets"] == 1
        assert "by_type" in data
        assert "risk_distribution" in data


@pytest.mark.asyncio
async def test_get_network_topology(mock_db_session, auth_override):
    asset = MagicMock()
    asset.id = uuid4()
    asset.hostname = "gateway"
    asset.ip_address = "10.0.0.1"
    asset.asset_type = "firewall"
    asset.risk_score = 5.0

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [asset]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/assets/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 1
