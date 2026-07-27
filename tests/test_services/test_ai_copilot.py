import pytest
from unittest.mock import MagicMock, AsyncMock
from uuid import uuid4
from httpx import AsyncClient, ASGITransport
from services.ai_copilot.main import app
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
async def test_chat_unauthorized():
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/copilot/chat",
            json={"message": "Show me critical alerts"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_chat(auth_override):
    from services.ai_copilot.ai.llm_client import llm_client

    llm_client.chat = AsyncMock(return_value="Here are your critical alerts for today.")

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/copilot/chat",
            json={"message": "Show me critical alerts"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "response" in data
        assert data["response"] == "Here are your critical alerts for today."
        assert "conversation_id" in data
        assert "suggestions" in data
        assert "actions" in data


@pytest.mark.asyncio
async def test_chat_with_conversation_id(auth_override):
    from services.ai_copilot.ai.llm_client import llm_client

    llm_client.chat = AsyncMock(return_value="Continuing our analysis.")
    conv_id = str(uuid4())

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/copilot/chat",
            json={
                "message": "What about lateral movement?",
                "conversation_id": conv_id,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["conversation_id"] == conv_id
        assert data["response"] == "Continuing our analysis."


@pytest.mark.asyncio
async def test_investigate_alert(auth_override):
    from services.ai_copilot.ai.llm_client import llm_client
    from core.elastic import elastic_client

    llm_client.chat = AsyncMock(return_value="Investigation complete. Root cause: C2 communication detected.")
    elastic_client.client.get = AsyncMock(return_value={"_source": {"id": "alert-123", "title": "Malware Detected"}})
    elastic_client.client.search = AsyncMock(return_value={"hits": {"hits": []}})

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/copilot/investigate/alert-123")
        assert resp.status_code == 200
        data = resp.json()
        assert data["alert_id"] == "alert-123"
        assert "summary" in data
        assert "root_cause" in data
        assert "recommended_actions" in data
        assert "confidence_score" in data


@pytest.mark.asyncio
async def test_summarize_incident_not_found(mock_db_session, auth_override):
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db_session.execute.return_value = mock_result

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(f"/api/v1/copilot/summarize/{uuid4()}")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_security_query(auth_override):
    from services.ai_copilot.ai.llm_client import llm_client

    llm_client.chat = AsyncMock(return_value="The best practice for credential management is to use MFA and rotate keys regularly.")

    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/copilot/query",
            json={"query": "What are best practices for credential management?"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "answer" in data
        assert "confidence" in data
        assert "data_sources_used" in data
        assert data["confidence"] == 0.95


@pytest.mark.asyncio
async def test_get_conversation_not_found(auth_override):
    transport = ASGITransport(app=app, )
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/copilot/conversation/{uuid4()}")
        assert resp.status_code == 404
