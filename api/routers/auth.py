"""Authentication and API key management endpoints."""
import logging

from fastapi import APIRouter, Depends, HTTPException

from api.deps import auth_service, get_current_user
from api.models import RegisterRequest

logger = logging.getLogger("picoshogun.auth")

router = APIRouter(prefix="/auth")


@router.post("/register", tags=["Authentication"])
async def register(request: RegisterRequest):
    """Register a new user account."""
    try:
        user_id = auth_service.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            role=request.role,
        )
        if not user_id:
            raise HTTPException(status_code=409, detail="Username already exists")
        return {"user_id": user_id, "username": request.username, "role": request.role}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


@router.post("/login", tags=["Authentication"])
async def login(username: str, password: str):
    """Authenticate and receive a JWT access token."""
    token = auth_service.authenticate(username, password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_info = auth_service.validate_token(token)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_info.get("id"),
        "role": user_info.get("role"),
    }


@router.post("/api-key", tags=["Authentication"])
async def create_api_key(
    request: dict,
    user: dict = Depends(get_current_user),
):
    """Create a new API key."""
    key_name = request.get("name", "default")
    api_key = auth_service.create_api_key(user["id"], name=key_name)
    return {"api_key": api_key, "name": key_name}


@router.post("/api-key/{key_id}/rotate", tags=["Authentication"])
async def rotate_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    """Rotate (regenerate) an API key."""
    new_key = auth_service.rotate_api_key(key_id, user["id"])
    if not new_key:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"api_key": new_key, "message": "API key rotated successfully"}


@router.delete("/api-key/{key_id}", tags=["Authentication"], status_code=204)
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    """Revoke (delete) an API key."""
    success = auth_service.revoke_api_key(key_id, user["id"])
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
