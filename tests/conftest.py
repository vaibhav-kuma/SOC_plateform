import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime, timezone

from core.security import create_access_token
from core.redis import redis_client
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.database import init_db, close_db


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db_session():
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_result.scalar.return_value = None
    mock_result.first.return_value = None
    mock_result.all.return_value = []
    mock_result.scalars.return_value.all.return_value = []
    mock_result.scalars.return_value.first.return_value = None
    session.execute = AsyncMock(return_value=mock_result)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    session.add = MagicMock()
    session.refresh = AsyncMock()
    session.flush = AsyncMock()
    return session


@pytest.fixture
def mock_current_user():
    return {
        "sub": str(uuid4()),
        "org_id": str(uuid4()),
        "role": "admin",
        "permissions": ["*"],
        "type": "access",
        "mfa_verified": True,
    }


@pytest.fixture
def auth_headers(mock_current_user):
    token = create_access_token(mock_current_user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def mock_redis():
    with patch.object(redis_client, "client", None):
        yield


@pytest.fixture(autouse=True)
def mock_elastic():
    es = AsyncMock()
    es.count = AsyncMock(return_value=0)
    es.get = AsyncMock(return_value=None)
    es.search = AsyncMock(return_value={"hits": {"hits": []}})
    es.index = AsyncMock()
    es.ping = AsyncMock(return_value=True)
    with patch.object(elastic_client, "client", es):
        yield


@pytest.fixture(autouse=True)
def mock_kafka():
    kp = AsyncMock()
    kp.start = AsyncMock()
    kp.stop = AsyncMock()
    with patch.object(kafka_client, "producer", kp):
        yield


@pytest.fixture(autouse=True)
def mock_lifespan_deps():
    with patch("core.database.init_db", AsyncMock()):
        with patch("core.database.close_db", AsyncMock()):
            with patch.object(redis_client, "start", AsyncMock()):
                with patch.object(redis_client, "stop", AsyncMock()):
                    with patch.object(elastic_client, "start", AsyncMock()):
                        with patch.object(elastic_client, "stop", AsyncMock()):
                            with patch.object(kafka_client, "start_producer", AsyncMock()):
                                with patch.object(kafka_client, "stop_producer", AsyncMock()):
                                    with patch.object(kafka_client, "stop_all_consumers", AsyncMock()):
                                        yield


def create_mock_user():
    user = MagicMock()
    user.id = uuid4()
    user.email = "admin@socplatform.io"
    user.password_hash = None
    user.is_active = True
    user.mfa_enabled = False
    user.mfa_secret = None
    user.role = "admin"
    user.org_id = uuid4()
    user.permissions = ["*"]
    user.last_login = None
    user.full_name = "Admin User"
    return user
