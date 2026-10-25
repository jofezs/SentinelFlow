from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "postgresql+asyncpg://sentinelflow:sentinelflow@localhost:5432/sentinelflow"


class Settings(BaseSettings):
    """Gateway configuration, read from SENTINELFLOW_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", env_file=".env", extra="ignore")

    database_url: str = DEFAULT_DATABASE_URL
    admin_token: SecretStr = Field(min_length=16)
    log_level: str = "INFO"
