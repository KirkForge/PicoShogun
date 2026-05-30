"""JSON output formatter for sandbox results."""
from __future__ import annotations

import json
from typing import IO

from ..models import SandboxResult


def format_json(result: SandboxResult, output: IO[str] | None = None) -> str:
    text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
