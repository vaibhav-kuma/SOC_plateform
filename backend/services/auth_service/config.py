from pydantic_settings import BaseSettings


class AuthSettings(BaseSettings):
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 30
    PASSWORD_MIN_LENGTH: int = 12
    SESSION_EXPIRE_HOURS: int = 24

    class Config:
        env_file = ".env"
        extra = "allow"


auth_settings = AuthSettings()
