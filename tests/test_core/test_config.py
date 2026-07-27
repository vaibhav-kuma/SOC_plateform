import pytest


def test_settings_defaults():
    from core.config import Settings
    s = Settings(_env_file=None)
    assert s.APP_NAME == "SOC Platform"
    assert s.API_V1_PREFIX == "/api/v1"
    assert s.DEBUG is False
    assert s.ENV == "development"
    assert s.JWT_ALGORITHM == "RS256"
    assert s.JWT_ACCESS_TOKEN_EXPIRE_MINUTES == 15
    assert s.MFA_ISSUER_NAME == "SOCPlatform"
    assert s.LLM_PROVIDER == "gemini"
    assert s.ELASTICSEARCH_VERIFY_CERTS is True
    assert s.ELASTICSEARCH_MAX_RETRIES == 3
    assert s.REDIS_SOCKET_TIMEOUT == 5
    assert s.REDIS_HEALTH_CHECK_INTERVAL == 30


def test_cors_origins_property():
    from core.config import Settings
    s = Settings(_env_file=None, CORS_ORIGINS='["http://localhost:3000","http://example.com"]')
    origins = s.cors_origins
    assert len(origins) == 2
    assert "http://localhost:3000" in origins
    assert "http://example.com" in origins


def test_es_hosts_property():
    from core.config import Settings
    s = Settings(_env_file=None, ELASTICSEARCH_HOSTS='["http://es1:9200","http://es2:9200"]')
    hosts = s.es_hosts
    assert len(hosts) == 2
    assert "http://es1:9200" in hosts
    assert "http://es2:9200" in hosts


def test_settings_validation_invalid_env():
    from core.config import Settings
    with pytest.raises(ValueError, match="ENV must be one of"):
        Settings(_env_file=None, ENV="invalid")


def test_settings_validation_production_db_password():
    from core.config import Settings
    with pytest.raises(ValueError, match="Default database password not allowed in production"):
        Settings(_env_file=None, ENV="production", DATABASE_URL="postgresql+asyncpg://socuser:socpass@localhost:5434/socplatform")


def test_settings_validation_invalid_llm_provider():
    from core.config import Settings
    with pytest.raises(ValueError, match="LLM_PROVIDER must be one of"):
        Settings(_env_file=None, LLM_PROVIDER="invalid")


def test_settings_validation_invalid_log_level():
    from core.config import Settings
    with pytest.raises(ValueError, match="LOG_LEVEL must be one of"):
        Settings(_env_file=None, LOG_LEVEL="INVALID")


def test_settings_validation_cors_wildcard_production():
    from core.config import Settings
    with pytest.raises(ValueError, match="CORS wildcard not allowed in production"):
        Settings(_env_file=None, ENV="production", CORS_ORIGINS='["*"]')


def test_settings_singleton():
    from core.config import settings
    assert settings.APP_NAME == "SOC Platform"
    assert hasattr(settings, "DATABASE_URL")
    assert hasattr(settings, "REDIS_URL")
    assert hasattr(settings, "KAFKA_BOOTSTRAP_SERVERS")
    assert hasattr(settings, "MFA_SECRET_ENCRYPTION_KEY")
