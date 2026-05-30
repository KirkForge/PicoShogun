"""L2 supply chain scan and L3 sandbox endpoints (API v1).

These endpoints require the picodome package and return 501 if unavailable.
"""
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from api.deps import require_role
from api.models import SandboxRunRequest, SandboxRunResponse, ScanRequest, ScanResponse

logger = logging.getLogger("picoshogun.scans")

router = APIRouter()


@router.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    user: dict = Depends(require_role("viewer")),
):
    """Run an L2 supply chain scan on a project directory."""
    try:
        from pico_dome.L2_validation.engine import create_default_engine as _create_engine
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="L2 scan engine requires the picodome package. Install with: pip install picodome",
        ) from None

    target = Path(request.target).resolve()
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {request.target}")

    engine = _create_engine()
    result = engine.scan(target, rules=request.rules)

    return ScanResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        target=result.target,
        engine_version=result.engine_version,
        findings_count=len(result.findings),
        findings=[f.to_dict() for f in result.findings],
        stats=result.stats.to_dict(),
    )


@router.get("/scans/rules", tags=["Scans"])
async def list_scan_rules(user: dict = Depends(require_role("viewer"))):
    """List available L2 supply chain scanner rules.

    Requires the picodome package: pip install picodome
    """
    raise HTTPException(
        status_code=501,
        detail="L2 scan rules require the picodome package. Install with: pip install picodome",
    )


@router.post("/sandboxes", response_model=SandboxRunResponse, tags=["Sandbox"])
async def run_sandbox(
    request: SandboxRunRequest,
    user: dict = Depends(require_role("operator")),
):
    """Run a command under L3 sandbox policy.

    Requires the picodome package: pip install picodome
    """
    raise HTTPException(
        status_code=501,
        detail="L3 sandbox endpoint requires the picodome package. Install with: pip install picodome",
    )


@router.get("/sandboxes/policies/default", tags=["Sandbox"])
async def get_default_policy(user: dict = Depends(require_role("viewer"))):
    """Get the default L3 sandbox policy.

    Requires the picodome package: pip install picodome
    """
    raise HTTPException(
        status_code=501,
        detail="L3 sandbox policy requires the picodome package. Install with: pip install picodome",
    )
