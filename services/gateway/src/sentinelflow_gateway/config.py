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
    # Prometheus metrics are served on a separate port (0 disables), so they are
    # scrapeable inside the cluster without being exposed through the public API.
    metrics_port: int = 9100


class Settings(ServiceSettings):
    """HTTP API configuration."""

    admin_token: SecretStr = Field(min_length=16)


class WorkerSettings(ServiceSettings):
    """Background worker configuration (outbox relay + results ingestion)."""

    nats_url: str = "nats://127.0.0.1:4222"
    relay_poll_interval: float = 0.5
    relay_batch_size: int = 100


class NotifierSettings(ServiceSettings):
    """Webhook notifier configuration."""

    poll_interval: float = 1.0
    batch_size: int = 20
    max_attempts: int = 6
    request_timeout: float = 10.0
    # Comma-separated exact hostnames allowed to resolve to private IPs (dev receivers).
    webhook_private_hosts: str = ""
