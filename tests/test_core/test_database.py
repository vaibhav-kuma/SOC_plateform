import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.database import get_session, init_db, close_db, engine, check_db_connection


@pytest.mark.asyncio
async def test_get_session():
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.close = AsyncMock()

    mock_factory = MagicMock(return_value=mock_session)

    with patch("core.database.async_session_factory", mock_factory):
        async for session in get_session():
            assert session is mock_session
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()


@pytest.mark.asyncio
async def test_get_session_rollback_on_error():
    mock_session = AsyncMock()
    mock_session.commit = AsyncMock(side_effect=Exception("DB error"))
    mock_session.rollback = AsyncMock()
    mock_session.close = AsyncMock()

    mock_factory = MagicMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
    mock_factory.return_value.__aexit__ = AsyncMock()

    with patch("core.database.async_session_factory", mock_factory):
        gen = get_session()
        try:
            await gen.__anext__()
            await gen.__anext__()
        except StopAsyncIteration:
            pass
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


@pytest.mark.asyncio
async def test_init_db():
    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock()
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock()

    with patch("core.database.engine") as mock_eng:
        mock_eng.begin.return_value = mock_ctx
        await init_db()
        mock_conn.run_sync.assert_called_once()


@pytest.mark.asyncio
async def test_close_db():
    mock_engine = AsyncMock()

    with patch("core.database.engine", mock_engine):
        await close_db()
        mock_engine.dispose.assert_called_once()


def test_engine_created():
    assert engine is not None
    assert hasattr(engine, "begin")
    assert hasattr(engine, "dispose")


def test_base_class():
    from core.database import Base
    assert hasattr(Base, "metadata")
    assert hasattr(Base.metadata, "create_all")
    assert hasattr(Base.metadata, "drop_all")


@pytest.mark.asyncio
async def test_check_db_connection_success():
    mock_conn = AsyncMock()
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock()

    with patch("core.database.engine") as mock_eng:
        mock_eng.connect.return_value = mock_ctx
        result = await check_db_connection()
        assert result is True
        mock_conn.execute.assert_called_once_with("SELECT 1")


@pytest.mark.asyncio
async def test_check_db_connection_failure():
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("core.database.engine") as mock_eng:
        mock_eng.connect = AsyncMock(return_value=mock_ctx)
        result = await check_db_connection()
        assert result is False
