"""Enterprise configuration management for Shogun."""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

@dataclass
class DatabaseConfig:
    path: Path = BASE_DIR / "shogun.db"
    backup_dir: Path = BASE_DIR / "backups"
    max_connections: int = 10
    timeout: int = 30
    backup_retention_days: int = 30
    journal_mode: str = "WAL"  # WAL | DELETE | TRUNCATE | PERSIST | MEMORY
    synchronous: str = "NORMAL"  # OFF | NORMAL | FULL
    wal_checkpoint_threshold: int = 1000  # pages before auto-checkpoint

@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8765
    workers: int = 4
    reload: bool = False
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    api_prefix: str = "/api/v1"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"

@dataclass
class SecurityConfig:
    secret_key: str = field(default_factory=lambda: os.environ.get("SHOGUN_SECRET_KEY", "change-me-in-production"))
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    password_hash_rounds: int = 12
    allowed_hosts: list[str] = field(default_factory=lambda: ["*"])
    rate_limit: str = "100/minute"
    ddos_shield_enabled: bool = field(default_factory=lambda: os.environ.get("SHOGUN_DDOS_SHIELD", "false").lower() == "true")
    ssl_cert_path: Path | None = None
    ssl_key_path: Path | None = None

@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    max_bytes: int = 10_000_000  # 10MB
    backup_count: int = 10
    log_dir: Path = BASE_DIR / "logs"
    structured: bool = True  # JSON logging for production

@dataclass
class AlertConfig:
    discord_webhook: str | None = field(default_factory=lambda: os.environ.get("DISCORD_WEBHOOK_URL"))
    slack_webhook: str | None = field(default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL"))
    email_smtp_host: str | None = field(default_factory=lambda: os.environ.get("SMTP_HOST"))
    email_smtp_port: int = int(os.environ.get("SMTP_PORT", "587"))
    email_smtp_user: str | None = field(default_factory=lambda: os.environ.get("SMTP_USER"))
    email_smtp_password: str | None = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD"))
    email_smtp_use_ssl: bool = False
    email_smtp_starttls: bool = True
    email_from: str | None = field(default_factory=lambda: os.environ.get("EMAIL_FROM", "secdev@localhost"))
    email_to: list[str] = field(default_factory=lambda: [
        addr.strip()
        for addr in os.environ.get("EMAIL_TO", "").split(",")
        if addr.strip()
    ])
    cooldown_seconds: int = 300
    max_retries: int = 3

@dataclass
class OrchestratorConfig:
    max_concurrent_projects: int = 5
    default_timeout: int = 300  # seconds
    retry_failed: bool = True
    retry_max: int = 3
    retry_delay: int = 60  # seconds
    schedule_enabled: bool = True
    health_check_interval: int = 60  # seconds

@dataclass
class Settings:
    env: str = field(default_factory=lambda: os.environ.get("SHOGUN_ENV", "development"))
    debug: bool = field(default_factory=lambda: os.environ.get("SHOGUN_DEBUG", "false").lower() == "true")
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    api: APIConfig = field(default_factory=APIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)

    def is_production(self) -> bool:
        return self.env == "production"

    def validate(self) -> list[str]:
        """Validate configuration and return list of issues."""
        issues = []

        if self.is_production():
            if self.security.secret_key == "change-me-in-production":
                issues.append("SECURITY: Default secret key in production")
            if not self.security.ssl_cert_path:
                issues.append("SECURITY: No SSL certificate configured")
            if self.debug:
                issues.append("SECURITY: Debug mode enabled in production")
            if "*" in self.security.allowed_hosts:
                issues.append("SECURITY: Wildcard allowed hosts in production")

        return issues

    @classmethod
    def from_file(cls, path: Path) -> "Settings":
        """Load settings from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def to_file(self, path: Path):
        """Save settings to JSON file."""
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2, default=str)

# Global settings instance
settings = Settings()
