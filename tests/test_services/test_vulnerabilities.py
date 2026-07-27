import pytest
from unittest.mock import MagicMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.vuln_scanner.main import app
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
async def test_list_vulnerabilities_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_vulnerabilities(mock_db_session, auth_override):
    vuln = MagicMock()
    vuln.id = uuid4()
    vuln.asset_id = uuid4()
    vuln.cve_id = "CVE-2024-1234"
    vuln.cvss_score = 8.5
    vuln.severity = "high"
    vuln.description = "Remote code execution"
    vuln.exploit_available = True
    vuln.remediation = "Apply vendor patch"
    vuln.status = "open"
    vuln.discovered_at = None
    vuln.created_at = None
    vuln.updated_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [vuln]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["cve_id"] == "CVE-2024-1234"
        assert data[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_list_vulnerabilities_with_filters(mock_db_session, auth_override):
    vuln = MagicMock()
    vuln.id = uuid4()
    vuln.asset_id = uuid4()
    vuln.cve_id = "CVE-2024-5678"
    vuln.cvss_score = 9.0
    vuln.severity = "critical"
    vuln.description = "Critical RCE"
    vuln.exploit_available = True
    vuln.remediation = "Update immediately"
    vuln.status = "open"
    vuln.discovered_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [vuln]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/vulnerabilities?severity=critical&status=open")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_get_vulnerability(mock_db_session, auth_override):
    vuln_id = uuid4()
    vuln = MagicMock()
    vuln.id = vuln_id
    vuln.asset_id = uuid4()
    vuln.cve_id = "CVE-2024-1234"
    vuln.cvss_score = 8.5
    vuln.severity = "high"
    vuln.description = "Remote code execution"
    vuln.exploit_available = True
    vuln.remediation = "Apply vendor patch"
    vuln.status = "open"
    vuln.discovered_at = None
    vuln.metadata = {}
    vuln.created_at = None
    vuln.updated_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = vuln
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/vulnerabilities/{vuln_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2024-1234"
        assert data["cvss_score"] == 8.5


@pytest.mark.asyncio
async def test_get_vulnerability_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/vulnerabilities/{uuid4()}")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_vuln_stats(mock_db_session, auth_override):
    vuln = MagicMock()
    vuln.severity = "high"
    vuln.status = "open"
    vuln.cve_id = "CVE-2024-1234"
    vuln.cvss_score = 8.5

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [vuln, vuln]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/vulnerabilities/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["high"] == 2
        assert "avg_cvss" in data
        assert "patched_percentage" in data


@pytest.mark.asyncio
async def test_update_vuln_status(mock_db_session, auth_override):
    vuln = MagicMock()
    vuln.id = uuid4()
    vuln.status = "open"
    vuln.fixed_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = vuln
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.patch(f"/api/v1/vulnerabilities/{vuln.id}/status?status=fixed")
        assert resp.status_code == 200
        data = resp.json()
        assert "fixed" in data["message"]


@pytest.mark.asyncio
async def test_update_vuln_status_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.patch(f"/api/v1/vulnerabilities/{uuid4()}/status?status=accepted")
        assert resp.status_code == 404
