"""JSON output formatter for scan results."""
from __future__ import annotations

import json
from typing import IO

from ..models import ScanResult


def format_json(result: ScanResult, output: IO[str] | None = None) -> str:
    """
    Format a ScanResult as JSON.

    Args:
        result: The scan result to format.
        output: Optional writable stream. If provided, writes to it.

    Returns:
        JSON string representation of the scan result.
    """
    text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
