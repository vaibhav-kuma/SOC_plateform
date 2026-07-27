from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, ValidationInfo
from typing import List, Optional
import json
import warnings
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=Path(__file__).parent.parent / ".env",
        case_sensitive=True,
        extra="ignore",
    )

    # App
    APP_NAME: str = "SOC Platform"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False
    ENV: str = "development"

    @field_validator("ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production"}
        if v not in allowed:
            raise ValueError(f"ENV must be one of {allowed}")
        return v

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://socuser:socpass@localhost:5434/socplatform"
    )
    SYNC_DATABASE_URL: str = Field(
        default="postgresql://socuser:socpass@localhost:5434/socplatform"
    )

    @field_validator("DATABASE_URL", "SYNC_DATABASE_URL")
    @classmethod
    def validate_db_urls(cls, v: str, info: ValidationInfo) -> str:
        if info.data.get("ENV") == "production" and "socpass" in v:
            raise ValueError("Default database password not allowed in production")
        return v

    # Database connection pool settings
    DB_MAX_CONNECTIONS: int = 100
    DB_MIN_CONNECTIONS: int = 1
    DB_CONNECT_TIMEOUT: int = 30
    DB_ASYNC_CONNECT_TIMEOUT: float = 5.0

    @field_validator("DB_MAX_CONNECTIONS")
    @classmethod
    def validate_max_connections(cls, v: int) -> int:
        if v > 200:
            raise ValueError("DB_MAX_CONNECTIONS should not exceed 200")
        return v

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None
    REDIS_SOCKET_TIMEOUT: int = 5
    REDIS_SOCKET_CONNECT_TIMEOUT: int = 5
    REDIS_HEALTH_CHECK_INTERVAL: int = 30

    # Elasticsearch
    ELASTICSEARCH_HOSTS: str = '["http://localhost:9200"]'
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None
    ELASTICSEARCH_VERIFY_CERTS: bool = True
    ELASTICSEARCH_TIMEOUT: int = 30
    ELASTICSEARCH_MAX_RETRIES: int = 3

    @field_validator("ELASTICSEARCH_USERNAME", "ELASTICSEARCH_PASSWORD")
    @classmethod
    def validate_es_auth(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        if info.data.get("ENV") == "production":
            if info.field_name == "ELASTICSEARCH_USERNAME" and not v:
                warnings.warn("ELASTICSEARCH_USERNAME not set in production", UserWarning)
            if info.field_name == "ELASTICSEARCH_PASSWORD" and not v:
                warnings.warn("ELASTICSEARCH_PASSWORD not set in production", UserWarning)
        return v

    @property
    def es_hosts(self) -> List[str]:
        return json.loads(self.ELASTICSEARCH_HOSTS)

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_SCHEMA_REGISTRY_URL: Optional[str] = None
    KAFKA_REQUEST_TIMEOUT_MS: int = 30000
    KAFKA_MAX_RETRIES: int = 3

    # JWT - RS256 recommended for production
    JWT_SECRET_KEY: str = Field(default="change-this-in-production")
    JWT_ALGORITHM: str = "RS256"
    JWT_PUBLIC_KEY_PATH: Optional[str] = "/run/secrets/jwt_public.key"
    JWT_PRIVATE_KEY_PATH: Optional[str] = "/run/secrets/jwt_private.key"
    JWT_PASSPHRASE: Optional[str] = None
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str, info: ValidationInfo) -> str:
        if info.data.get("ENV") == "production" and v == "change-this-in-production":
            raise ValueError("JWT_SECRET_KEY must be changed in production")
        if len(v) < 32:
            warnings.warn("JWT_SECRET_KEY should be at least 32 characters", UserWarning)
        return v

    # MFA
    MFA_ISSUER_NAME: str = "SOCPlatform"
    MFA_SECRET_ENCRYPTION_KEY: Optional[str] = None

    @field_validator("MFA_SECRET_ENCRYPTION_KEY")
    @classmethod
    def validate_mfa_encryption_key(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        if info.data.get("ENV") == "production" and not v:
            raise ValueError("MFA_SECRET_ENCRYPTION_KEY must be set in production")
        return v

    # LLM
    OPENAI_API_KEY: Optional[str] = None
    GOOGLE_GEMINI_API_KEY: Optional[str] = None
    LLM_PROVIDER: str = "gemini"
    LOCAL_LLM_URL: Optional[str] = None
    LOCAL_LLM_MODEL: Optional[str] = "llama3:8b"

    @field_validator("LLM_PROVIDER")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        allowed = {"openai", "gemini", "local"}
        if v not in allowed:
            raise ValueError(f"LLM_PROVIDER must be one of {allowed}")
        return v

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: str = Field(default='["http://localhost:3000","http://localhost:5173"]')

    @field_validator("CORS_ORIGINS")
    @classmethod
    def validate_cors_origins(cls, v: str, info: ValidationInfo) -> str:
        if info.data.get("ENV") == "production" and "*" in v:
            raise ValueError("CORS wildcard not allowed in production")
        return v

    @property
    def cors_origins(self) -> List[str]:
        return json.loads(self.CORS_ORIGINS)

    # Logging
    LOG_LEVEL: str = "INFO"
    JSON_LOGS: bool = True

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()


settings = Settings()
