from pydantic_settings import BaseSettings
from pydantic import ConfigDict

class Settings(BaseSettings):
    SECRET_KEY: str = "CHANGE_ACCESS_SECRET"
    REFRESH_SECRET_KEY: str = "CHANGE_REFRESH_SECRET"
    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    MAX_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCK_MINUTES: int = 15

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()