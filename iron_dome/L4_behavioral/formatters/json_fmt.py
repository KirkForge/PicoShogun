"""JSON output formatter for L4 behavioral analysis results."""
from __future__ import annotations

import json
from typing import IO

from ..models import AnalysisResult


def format_json(result: AnalysisResult, output: IO[str] | None = None) -> str:
    """Format an AnalysisResult as JSON."""
    text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
