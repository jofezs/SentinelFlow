from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# 127.0.0.1 rather than localhost: on Windows, localhost resolves to ::1 first and
# Docker publishes ports on IPv4 only, which stalls connections.
DEFAULT_DATABASE_URL = "postgresql+asyncpg://sentinelflow:sentinelflow@127.0.0.1:5432/sentinelflow"


class ServiceSettings(BaseSettings):
    """Shared configuration, read from SENTINELFLOW_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="SENTINELFLOW_", env_file=".env", extra="ignore")

    database_url: str = DEFAULT_DATABASE_URL
    log_level: str = "INFO"


class Settings(ServiceSettings):
    """HTTP API configuration."""

    admin_token: SecretStr = Field(min_length=16)


class WorkerSettings(ServiceSettings):
    """Background worker configuration (outbox relay + results ingestion)."""

    nats_url: str = "nats://127.0.0.1:4222"
    relay_poll_interval: float = 0.5
    relay_batch_size: int = 100
