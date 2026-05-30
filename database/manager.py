"""Database layer with migrations, connection pooling, and ORM-like interface."""
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from config.settings import settings


# ─── Python 3.12+ datetime adapter ─────────────────────────────────────
# Silence DeprecationWarning: default datetime adapter is deprecated
def _adapt_datetime(dt):
    """ISO 8601 adapter for Python 3.12+ sqlite3 datetime deprecation."""
    return dt.isoformat()


def _convert_timestamp(val):
    """Convert ISO 8601 timestamp string back to datetime."""
    if isinstance(val, bytes):
        val = val.decode()
    if val:
        return datetime.fromisoformat(val)
    return None


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)

logger = logging.getLogger("picoshogun.DB")


# ─── Abstract connection interface for future Postgres migration ────────
class ConnectionPool:
    """Abstract interface for database connection pooling.

    The current SQLite implementation uses thread-local connections.
    For a Postgres migration, implement this interface with
    ``asyncpg`` or ``psycopg`` connection pooling.
    """

    def acquire(self):
        """Get a connection from the pool."""
        raise NotImplementedError

    def release(self, conn):
        """Return a connection to the pool."""
        raise NotImplementedError

    def close_all(self):
        """Close all connections in the pool."""
        raise NotImplementedError


@dataclass
class Migration:
    version: int
    name: str
    sql: str

MIGRATIONS = [
    Migration(1, "initial", """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            name TEXT
        );

        CREATE TABLE IF NOT EXISTS project_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            org_id INTEGER,
            run_start TIMESTAMP,
            run_end TIMESTAMP,
            status TEXT,
            exit_code INTEGER,
            output TEXT,
            stderr TEXT,
            duration_seconds REAL,
            alerts_generated INTEGER DEFAULT 0,
            intelligence_extracted TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id)
        );

        CREATE TABLE IF NOT EXISTS intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_project TEXT,
            intel_type TEXT,
            severity TEXT,
            data TEXT,
            related_projects TEXT,
            action_taken TEXT,
            confidence REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            channel TEXT,
            sent BOOLEAN DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            metric_name TEXT,
            metric_value REAL,
            unit TEXT,
            labels TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT,
            category TEXT,
            priority INTEGER,
            status TEXT,
            version TEXT,
            last_run TIMESTAMP,
            run_count INTEGER DEFAULT 0,
            success_rate REAL DEFAULT 0.0,
            avg_duration REAL DEFAULT 0.0,
            metadata TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component TEXT,
            status TEXT,
            message TEXT,
            latency_ms REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_project_runs_project ON project_runs(project_id, run_start);
        CREATE INDEX IF NOT EXISTS idx_project_runs_status ON project_runs(status);
        CREATE INDEX IF NOT EXISTS idx_intelligence_severity ON intelligence(severity, created_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_sent ON alerts(sent, created_at);
        CREATE INDEX IF NOT EXISTS idx_metrics_project ON metrics(project_id, metric_name, created_at);
    """),

    Migration(2, "add_users", """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'viewer',
            is_active BOOLEAN DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            name TEXT,
            permissions TEXT,
            expires_at TIMESTAMP,
            last_used TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            revoked_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """),

    Migration(3, "add_audit_log", """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user_id INTEGER,
            resource_type TEXT,
            resource_id TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, resource_type);
    """),

    Migration(4, "add_webhooks_scheduler", """
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            name TEXT,
            secret TEXT,
            active BOOLEAN DEFAULT 1,
            events TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            command TEXT NOT NULL,
            schedule TEXT NOT NULL,
            active BOOLEAN DEFAULT 1,
            last_run TIMESTAMP,
            next_run TIMESTAMP,
            run_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active);
        CREATE INDEX IF NOT EXISTS idx_jobs_active ON scheduled_jobs(active, next_run);
    """),

    Migration(5, "add_orgs", """
        CREATE TABLE IF NOT EXISTS orgs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL,
            owner_id INTEGER,
            tier TEXT DEFAULT 'free',
            api_key TEXT UNIQUE,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS org_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER,
            user_id INTEGER,
            role TEXT DEFAULT 'member',
            invited_at TIMESTAMP,
            joined_at TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS org_projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            org_id INTEGER,
            project_id TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_id) REFERENCES orgs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_orgs_slug ON orgs(slug);
        CREATE INDEX IF NOT EXISTS idx_orgs_key ON orgs(api_key);
        CREATE INDEX IF NOT EXISTS idx_org_members ON org_users(org_id, user_id);
    """),

    Migration(6, "add_org_id_to_runs_and_revoked_at", """
        -- Add org_id column to project_runs (P0 fix: get_usage() crashed)
        -- Using IF NOT EXISTS pattern via try/except at Python level for SQLite compat

        -- Add revoked_at column to api_keys (P1 fix: rotate_api_key crashed)
        -- Same: handled idempotently

        -- Add index for org-filtered run queries
        CREATE INDEX IF NOT EXISTS idx_project_runs_org ON project_runs(org_id, run_start);
    """),
    Migration(7, "add_anomaly_alerts", """
        CREATE TABLE IF NOT EXISTS anomaly_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            value REAL,
            threshold REAL,
            comparison TEXT,
            severity TEXT DEFAULT 'warning',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_rule ON anomaly_alerts(rule_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_anomaly_alerts_severity ON anomaly_alerts(severity, created_at);
    """)]


class DatabaseManager:
    """Thread-safe database manager with connection pooling."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.database.path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._ensure_dir()
        self._init_migrations()

    def _ensure_dir(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=settings.database.timeout,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            # WAL mode + sane defaults from config
            journal = settings.database.journal_mode.upper()
            sync_level = settings.database.synchronous.upper()
            self._local.conn.execute(f"PRAGMA journal_mode={journal}")
            self._local.conn.execute(f"PRAGMA synchronous={sync_level}")
            # Auto-checkpoint at configured threshold (WAL only)
            if journal == "WAL":
                threshold = settings.database.wal_checkpoint_threshold
                self._local.conn.execute(f"PRAGMA wal_autocheckpoint={threshold}")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        conn = self._get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def execute(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute SQL and return results."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(sql, params)
            return cursor.fetchall()

    def execute_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        """Execute SQL and return first result."""
        results = self.execute(sql, params)
        return results[0] if results else None

    def execute_insert(self, sql: str, params: tuple = ()) -> int:
        """Execute INSERT and return last row ID."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.lastrowid

    def _init_migrations(self):
        """Initialize and run pending migrations."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                name TEXT
            )
        """)

        current_version = self.execute_one(
            "SELECT MAX(version) as v FROM schema_version"
        )
        current = current_version["v"] if current_version and current_version["v"] is not None else 0

        for migration in MIGRATIONS:
            if migration.version > current:
                logger.info(f"Applying migration {migration.version}: {migration.name}")
                for stmt in migration.sql.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        try:
                            self.execute(stmt + ";")
                        except Exception as e:
                            # Allow idempotent migration: ignore duplicate column/index errors
                            err_str = str(e).lower()
                            if "duplicate column" in err_str or "already exists" in err_str:
                                logger.debug(f"Migration idempotent skip: {e}")
                            else:
                                raise
                self.execute_insert(
                    "INSERT INTO schema_version (version, name) VALUES (?, ?)",
                    (migration.version, migration.name)
                )
                logger.info(f"Migration {migration.version} applied")

    def backup(self) -> Path:
        """Create a backup of the database."""
        backup_dir = settings.database.backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"shogun_{timestamp}.db"

        with self._lock:
            source = sqlite3.connect(str(self.db_path))
            dest = sqlite3.connect(str(backup_path))
            source.backup(dest)
            dest.close()
            source.close()

        logger.info(f"Database backed up to {backup_path}")
        return backup_path

    def close(self):
        """Close all connections."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

# Global instance
db = DatabaseManager()
