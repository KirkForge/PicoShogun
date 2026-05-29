"""
JSON formatter — deterministic output with sorted keys.

Produces the same JSON for the same ScanResult, every time.
"""
from picosentry.models import ScanResult


def format_json(result: ScanResult, indent: int = 2) -> str:
    """
    Format a ScanResult as deterministic JSON.

    Same input = same output. Sorted keys, no random IDs.
    """
    return result.to_json(indent=indent)
