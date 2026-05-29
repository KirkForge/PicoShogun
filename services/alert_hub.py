"""Enterprise alert hub with multi-channel delivery and deduplication."""
import logging
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from config.settings import settings
from database.manager import db

logger = logging.getLogger("shogun.Alerts")

class AlertHub:
    """Smart alerting with deduplication, escalation, and multi-channel delivery."""

    def __init__(self):
        self.recent_alerts = defaultdict(list)
        self.cooldown_seconds = settings.alerts.cooldown_seconds
        self.max_retries = settings.alerts.max_retries
        self._lock = threading.Lock()

    def send(self, project_id: str, alert_type: str, severity: str,
             message: str, channels: list[str] | None = None,
             metadata: dict | None = None) -> bool:
        """Send alert with deduplication and multi-channel routing."""

        if channels is None:
            channels = self._get_default_channels()

        # Deduplication check
        with self._lock:
            now = datetime.now(timezone.utc)
            key = f"{project_id}:{alert_type}"

            # Clean old entries
            self.recent_alerts[key] = [
                t for t in self.recent_alerts.get(key, [])
                if (now - t).total_seconds() < self.cooldown_seconds * 2
            ]

            # Check cooldown
            for prev in self.recent_alerts.get(key, []):
                if (now - prev).total_seconds() < self.cooldown_seconds:
                    logger.debug(f"Alert suppressed: {key}")
                    return False

            self.recent_alerts[key].append(now)

        # Store in DB
        alert_ids = []
        for channel in channels:
            alert_id = db.execute_insert("""
                INSERT INTO alerts (project_id, alert_type, severity, message, channel)
                VALUES (?, ?, ?, ?, ?)
            """, (project_id, alert_type, severity, message, channel))
            alert_ids.append(alert_id)

        # Deliver to channels
        success = False
        for i, channel in enumerate(channels):
            try:
                if channel == "discord":
                    self._discord_notify(project_id, severity, message, metadata)
                elif channel == "slack":
                    self._slack_notify(project_id, severity, message, metadata)
                elif channel == "email":
                    self._email_notify(project_id, severity, message)
                elif channel == "syslog":
                    self._syslog_notify(project_id, severity, message)

                # Mark as sent
                db.execute("""
                    UPDATE alerts SET sent = 1 WHERE id = ?
                """, (alert_ids[i],))
                success = True
            except Exception as e:
                logger.error(f"Alert delivery failed ({channel}): {e}")
                # Increment retry count
                db.execute("""
                    UPDATE alerts SET retry_count = retry_count + 1 WHERE id = ?
                """, (alert_ids[i],))

        logger.info(f"ALERT [{severity.upper()}] {project_id}: {message[:100]}")
        return success

    def _get_default_channels(self) -> list[str]:
        """Determine default channels based on configuration."""
        channels = ["syslog"]  # Always log to syslog

        if settings.alerts.discord_webhook:
            channels.append("discord")
        if settings.alerts.slack_webhook:
            channels.append("slack")
        if settings.alerts.email_smtp_host:
            channels.append("email")

        return channels

    def _discord_notify(self, project_id: str, severity: str, message: str,
                       metadata: dict | None = None):
        """Send rich embed to Discord webhook."""
        if not HAS_REQUESTS or not settings.alerts.discord_webhook:
            return

        colors = {
            "critical": 15158332,  # Red
            "high": 16711680,      # Dark red
            "medium": 16776960,    # Yellow
            "low": 65280,          # Green
            "info": 3447003        # Blue
        }

        embed = {
            "title": "🛡️ Shogun Alert",
            "description": message,
            "color": colors.get(severity, 3447003),
            "fields": [
                {"name": "Project", "value": project_id, "inline": True},
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Time", "value": datetime.now(timezone.utc).isoformat(), "inline": True}
            ],
            "footer": {"text": "Shogun Enterprise"}
        }

        if metadata:
            for key, value in metadata.items():
                if len(str(value)) < 1000:
                    embed["fields"].append({
                        "name": key,
                        "value": str(value)[:1000],
                        "inline": True
                    })

        payload = {"embeds": [embed]}

        try:
            requests.post(
                settings.alerts.discord_webhook,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error(f"Discord webhook failed: {e}")

    def _slack_notify(self, project_id: str, severity: str, message: str,
                     metadata: dict | None = None):
        """Send formatted message to Slack webhook."""
        if not HAS_REQUESTS or not settings.alerts.slack_webhook:
            return

        colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00FF00",
            "info": "#0066FF"
        }

        payload = {
            "attachments": [{
                "color": colors.get(severity, "#808080"),
                "title": f"Shogun Alert: {project_id}",
                "text": message,
                "fields": [
                    {"title": "Severity", "value": severity.upper(), "short": True},
                    {"title": "Time", "value": datetime.now(timezone.utc).isoformat(), "short": True}
                ]
            }]
        }

        if metadata:
            for key, value in metadata.items():
                payload["attachments"][0]["fields"].append({
                    "title": key,
                    "value": str(value)[:1000],
                    "short": True
                })

        try:
            requests.post(
                settings.alerts.slack_webhook,
                json=payload,
                timeout=5
            )
        except Exception as e:
            logger.error(f"Slack webhook failed: {e}")

    def _email_notify(self, project_id: str, severity: str, message: str):
        """Send email notification via SMTP with TLS/auth support."""
        import smtplib
        from email.mime.text import MIMEText

        if not settings.alerts.email_smtp_host or not settings.alerts.email_to:
            return

        try:
            msg = MIMEText(f"""
Shogun Alert

Project: {project_id}
Severity: {severity.upper()}
Time: {datetime.now(timezone.utc).isoformat()}

{message}
            """)

            msg["Subject"] = f"[Shogun] {severity.upper()}: {project_id}"
            msg["From"] = settings.alerts.email_from or "secdev@localhost"
            msg["To"] = ", ".join(settings.alerts.email_to)

            # Choose connection method: SSL direct or STARTTLS
            if settings.alerts.email_smtp_use_ssl:
                server = smtplib.SMTP_SSL(
                    settings.alerts.email_smtp_host,
                    settings.alerts.email_smtp_port
                )
            else:
                server = smtplib.SMTP(
                    settings.alerts.email_smtp_host,
                    settings.alerts.email_smtp_port
                )

            # Upgrade to TLS if STARTTLS requested (no-op if already SSL)
            if settings.alerts.email_smtp_starttls and not settings.alerts.email_smtp_use_ssl:
                server.starttls()

            # Authenticate if credentials provided
            if settings.alerts.email_smtp_user and settings.alerts.email_smtp_password:
                server.login(
                    settings.alerts.email_smtp_user,
                    settings.alerts.email_smtp_password
                )

            server.send_message(msg)
            server.quit()
            logger.info(f"Email alert sent to {len(settings.alerts.email_to)} recipients")

        except Exception as e:
            logger.error(f"Email notification failed: {e}")

    def _syslog_notify(self, project_id: str, severity: str, message: str):
        """Log to syslog."""
        import syslog

        levels = {
            "critical": syslog.LOG_CRIT,
            "high": syslog.LOG_ERR,
            "medium": syslog.LOG_WARNING,
            "low": syslog.LOG_NOTICE,
            "info": syslog.LOG_INFO
        }

        try:
            syslog.syslog(
                levels.get(severity, syslog.LOG_INFO),
                f"Shogun[{project_id}]: [{severity.upper()}] {message[:500]}"
            )
        except Exception:
            pass  # Syslog might not be available

    def get_alert_stats(self, hours: int = 24) -> dict[str, Any]:
        """Get alert statistics."""
        rows = db.execute("""
            SELECT
                severity,
                channel,
                sent,
                COUNT(*) as count
            FROM alerts
            WHERE created_at > datetime('now', '-' || ? || ' hours')
            GROUP BY severity, channel, sent
        """, (hours,))

        stats = defaultdict(lambda: defaultdict(int))
        for row in rows:
            stats[row["severity"]]["total"] += row["count"]
            if row["sent"]:
                stats[row["severity"]]["sent"] += row["count"]
            else:
                stats[row["severity"]]["pending"] += row["count"]

        return dict(stats)
