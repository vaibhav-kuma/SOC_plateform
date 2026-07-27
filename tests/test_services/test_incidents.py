import pytest
from unittest.mock import MagicMock, AsyncMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.incident_response.main import app
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
async def test_list_incidents_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/incidents")
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_incidents(mock_db_session, auth_override):
    incident = MagicMock()
    incident.id = uuid4()
    incident.title = "Suspicious PowerShell Activity"
    incident.description = "Detected encoded PowerShell command execution"
    incident.severity = "high"
    incident.status = "open"
    incident.alert_ids = []
    incident.assignee_id = None
    incident.playbook_id = None
    incident.timeline = []
    incident.tags = []
    incident.ai_narrative = None
    incident.created_at = None
    incident.updated_at = None
    incident.resolved_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [incident]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/incidents")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["title"] == "Suspicious PowerShell Activity"
        assert data[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_create_incident(mock_db_session, auth_override):
    from datetime import datetime, timezone

    incident_id = uuid4()

    async def _refresh_side_effect():
        incident.id = incident_id

    mock_db_session.refresh = AsyncMock(side_effect=_refresh_side_effect)

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/incidents",
            json={
                "title": "New Incident",
                "description": "Test description",
                "severity": "high",
                "alert_ids": [],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "New Incident"
        assert data["severity"] == "high"


@pytest.mark.asyncio
async def test_get_incident(mock_db_session, auth_override):
    incident_id = uuid4()
    incident = MagicMock()
    incident.id = incident_id
    incident.title = "Ransomware Detected"
    incident.description = "File encryption activity detected"
    incident.severity = "critical"
    incident.status = "investigating"
    incident.alert_ids = ["alert-1", "alert-2"]
    incident.assignee_id = uuid4()
    incident.playbook_id = None
    incident.timeline = []
    incident.tags = ["ransomware", "critical"]
    incident.ai_narrative = None
    incident.created_at = None
    incident.updated_at = None
    incident.resolved_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = incident
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/incidents/{incident_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "Ransomware Detected"
        assert data["severity"] == "critical"


@pytest.mark.asyncio
async def test_get_incident_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/incidents/{uuid4()}")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_incident_stats(mock_db_session, auth_override):
    incident = MagicMock()
    incident.status = "open"
    incident.severity = "critical"
    incident.created_at = None
    incident.resolved_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [incident]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/incidents/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["open"] == 1
        assert data["critical"] == 1


@pytest.mark.asyncio
async def test_update_incident(mock_db_session, auth_override):
    incident_id = uuid4()
    incident = MagicMock()
    incident.id = incident_id
    incident.title = "Old Title"
    incident.description = "Old description"
    incident.severity = "medium"
    incident.status = "open"
    incident.alert_ids = []
    incident.assignee_id = None
    incident.playbook_id = None
    incident.timeline = []
    incident.tags = []
    incident.ai_narrative = None
    incident.created_at = None
    incident.updated_at = None
    incident.resolved_at = None

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = incident
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"status": "resolved"},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_playbooks(mock_db_session, auth_override):
    playbook = MagicMock()
    playbook.id = uuid4()
    playbook.name = "Ransomware Response"
    playbook.description = "Automated ransomware playbook"
    playbook.trigger_type = "alert_severity"
    playbook.steps = []
    playbook.is_active = True
    playbook.created_at = None

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [playbook]
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/incidents/playbooks")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "Ransomware Response"


@pytest.mark.asyncio
async def test_assign_incident(mock_db_session, auth_override):
    incident_id = uuid4()
    assignee_id = uuid4()
    incident = MagicMock()
    incident.id = incident_id
    incident.assignee_id = None
    incident.timeline = []

    mock_incident_result = MagicMock()
    mock_incident_result.scalar_one_or_none.return_value = incident
    mock_user_result = MagicMock()
    mock_user_result.scalar_one_or_none.return_value = MagicMock()

    def execute_side_effect(query):
        from sqlalchemy.sql import Select
        from common.models.base import User, Incident
        q_str = str(query)
        if "FROM incidents" in q_str or "FROM incident" in q_str:
            return mock_incident_result
        if "FROM users" in q_str or "FROM user" in q_str:
            return mock_user_result
        return mock_incident_result

    mock_db_session.execute = AsyncMock(side_effect=execute_side_effect)

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/incidents/{incident_id}/assign?assignee_id={assignee_id}",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "assigned" in data["message"]
