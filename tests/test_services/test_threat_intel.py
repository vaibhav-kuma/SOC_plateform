import pytest
from unittest.mock import MagicMock, AsyncMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.threat_intel.main import app
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
async def test_list_iocs_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/iocs")
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_iocs(mock_db_session, auth_override):
    ioc = MagicMock()
    ioc.id = uuid4()
    ioc.ioc_type = "ip"
    ioc.ioc_value = "185.234.72.18"
    ioc.threat_score = 85.0
    ioc.source = "manual"
    ioc.tags = ["c2", "malicious"]
    ioc.is_active = True
    ioc.first_seen = None
    ioc.last_seen = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [ioc]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/iocs")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["ioc_value"] == "185.234.72.18"
        assert data[0]["ioc_type"] == "ip"


@pytest.mark.asyncio
async def test_list_iocs_with_filters(mock_db_session, auth_override):
    ioc = MagicMock()
    ioc.id = uuid4()
    ioc.ioc_type = "hash"
    ioc.ioc_value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ioc.threat_score = 92.0
    ioc.source = "virustotal"
    ioc.tags = ["malware", "trojan"]
    ioc.is_active = True
    ioc.first_seen = None
    ioc.last_seen = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [ioc]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/iocs?ioc_type=hash&min_score=50")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["ioc_type"] == "hash"


@pytest.mark.asyncio
async def test_create_ioc(mock_db_session, auth_override):
    ioc_id = uuid4()

    async def _refresh_side_effect():
        ioc.id = ioc_id
        ioc.is_active = True
        ioc.first_seen = None

    ioc = MagicMock()
    ioc.id = ioc_id
    ioc.ioc_type = "domain"
    ioc.ioc_value = "evil-malware.com"
    ioc.threat_score = 75.0
    ioc.source = "manual"
    ioc.tags = ["malware", "c2"]
    ioc.is_active = True
    ioc.first_seen = None
    ioc.last_seen = None

    mock_db_session.refresh = AsyncMock(side_effect=_refresh_side_effect)

    mock_existing = MagicMock()
    mock_existing.scalar_one_or_none.return_value = None

    def execute_side_effect(*args, **kwargs):
        return mock_existing

    mock_db_session.execute = AsyncMock(side_effect=execute_side_effect)

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intel/iocs",
            json={
                "ioc_type": "domain",
                "ioc_value": "evil-malware.com",
                "threat_score": 75,
                "source": "manual",
                "tags": ["malware", "c2"],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ioc_type"] == "domain"
        assert data["ioc_value"] == "evil-malware.com"


@pytest.mark.asyncio
async def test_create_ioc_duplicate(mock_db_session, auth_override):
    mock_existing = MagicMock()
    mock_existing.scalar_one_or_none.return_value = MagicMock()
    mock_db_session.execute.return_value = mock_existing

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intel/iocs",
            json={
                "ioc_type": "ip",
                "ioc_value": "10.0.0.1",
                "threat_score": 50,
                "source": "manual",
                "tags": [],
            },
        )
        assert resp.status_code == 409


@pytest.mark.asyncio
async def test_get_ioc(mock_db_session, auth_override):
    ioc_id = uuid4()
    ioc = MagicMock()
    ioc.id = ioc_id
    ioc.ioc_type = "ip"
    ioc.ioc_value = "10.0.0.1"
    ioc.threat_score = 50.0
    ioc.source = "manual"
    ioc.tags = []
    ioc.is_active = True
    ioc.first_seen = None
    ioc.last_seen = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = ioc
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/intel/iocs/{ioc_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ioc_value"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_get_ioc_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/intel/iocs/{uuid4()}")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_feeds(auth_override):
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/feeds")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 3


@pytest.mark.asyncio
async def test_list_actors(auth_override):
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/actors")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 2


@pytest.mark.asyncio
async def test_search_intel(mock_db_session, auth_override):
    ioc = MagicMock()
    ioc.id = uuid4()
    ioc.ioc_type = "ip"
    ioc.ioc_value = "185.234.72.18"
    ioc.threat_score = 85.0
    ioc.source = "manual"
    ioc.tags = ["c2"]
    ioc.is_active = True
    ioc.first_seen = None
    ioc.last_seen = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [ioc]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/intel/search",
            json={"query": "185.234", "max_results": 50},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1


@pytest.mark.asyncio
async def test_intel_stats(mock_db_session, auth_override):
    ioc = MagicMock()
    ioc.ioc_type = "ip"
    ioc.source = "manual"
    ioc.is_active = True
    ioc.threat_score = 75.0

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [ioc, ioc]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/intel/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_iocs"] == 2
        assert data["active_iocs"] == 2
        assert "by_type" in data
        assert "by_source" in data


@pytest.mark.asyncio
async def test_enrich_ioc(mock_db_session, auth_override):
    ioc_id = uuid4()
    ioc = MagicMock()
    ioc.id = ioc_id
    ioc.ioc_type = "ip"
    ioc.ioc_value = "185.234.72.18"
    ioc.threat_score = 85.0
    ioc.source = "manual"
    ioc.tags = ["c2"]
    ioc.is_active = True

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = ioc
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(f"/api/v1/intel/iocs/{ioc_id}/enrich")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ioc_value"] == "185.234.72.18"
        assert "reputation" in data
        assert "findings" in data
