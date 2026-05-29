"""Quick test: verify SMTP config loads from env vars."""
import os
import sys
from pathlib import Path

# Resolve project root (scripts/test_email_config.py → up one dir)
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Mock env vars for testing
os.environ.update({
    "SMTP_HOST": "smtp.test.example",
    "SMTP_PORT": "465",
    "SMTP_USER": "test_user",
    "SMTP_PASSWORD": "hunter2",
    "EMAIL_FROM": "alerts@shogun.example",
    "EMAIL_TO": "admin@example.com, oncall@example.com",
})

from config.settings import settings

assert settings.alerts.email_smtp_host == "smtp.test.example"
assert settings.alerts.email_smtp_port == 465
assert settings.alerts.email_smtp_user == "test_user"
assert settings.alerts.email_smtp_password == "hunter2"
assert settings.alerts.email_from == "alerts@shogun.example"
assert settings.alerts.email_to == ["admin@example.com", "oncall@example.com"]
assert settings.alerts.email_smtp_starttls is True
assert settings.alerts.email_smtp_use_ssl is False

print("✅ All email config tests passed")
