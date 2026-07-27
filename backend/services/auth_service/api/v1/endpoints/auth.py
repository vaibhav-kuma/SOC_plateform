from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import hashlib
import secrets

from core.database import get_session
from core.security import (
    verify_password, hash_password, create_access_token, create_refresh_token,
    decode_token, generate_mfa_secret, get_mfa_uri, verify_mfa_code,
    generate_api_key,
)
from core.redis import redis_client
from core.config import settings
from core.dependencies import get_current_user, require_permissions
from services.auth_service.models.schemas import (
    LoginRequest, LoginResponse, MFARegisterResponse, MFAVerifyRequest,
    MFALoginRequest, TokenRefreshRequest, TokenRefreshResponse,
    UserCreate, UserUpdate, UserResponse, UserCreateResponse,
    PasswordChangeRequest, OrganizationCreate, OrganizationResponse,
)
from services.auth_service.models.domain import RefreshToken
from common.models.base import User, Organization
from services.auth_service.config import auth_settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(request: Request, body: LoginRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is disabled")

    # Check lockout
    if redis_client.client:
        lockout_key = f"lockout:{user.id}"
        if await redis_client.get(lockout_key):
            raise HTTPException(status_code=429, detail="Account temporarily locked. Try again later.")

    user.last_login = datetime.now(timezone.utc)
    await session.commit()

    if user.mfa_enabled:
        mfa_session = secrets.token_urlsafe(32)
        if redis_client.client:
            await redis_client.set(f"mfa_session:{mfa_session}", str(user.id), ttl=300)
        return LoginResponse(
            access_token="", refresh_token="",
            expires_in=0, mfa_required=True, mfa_session_id=mfa_session,
        )

    return await _generate_token_response(user)


@router.post("/mfa/verify", response_model=LoginResponse)
async def verify_mfa(body: MFALoginRequest, session: AsyncSession = Depends(get_session)):
    user_id = await redis_client.get(f"mfa_session:{body.mfa_session_id}")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA session")

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not configured")

    if not verify_mfa_code(user.mfa_secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    await redis_client.delete(f"mfa_session:{body.mfa_session_id}")
    return await _generate_token_response(user)


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(body: TokenRefreshRequest, session: AsyncSession = Depends(get_session)):
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    stored = result.scalar_one_or_none()
    if not stored:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    payload = decode_token(body.refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    stored.is_revoked = True
    stored.revoked_at = datetime.now(timezone.utc)

    result = await session.execute(select(User).where(User.id == payload.get("sub")))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    await session.commit()
    return TokenRefreshResponse(
        access_token=create_access_token({"sub": str(user.id), "org_id": str(user.org_id), "role": user.role}),
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(
    body: TokenRefreshRequest,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    stored = result.scalar_one_or_none()
    if stored:
        stored.is_revoked = True
        stored.revoked_at = datetime.now(timezone.utc)
        await session.commit()
    return {"message": "Logged out successfully"}


@router.post("/mfa/setup", response_model=MFARegisterResponse)
async def setup_mfa(current_user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.id == current_user.get("sub")))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    secret = generate_mfa_secret()
    user.mfa_secret = secret
    user.mfa_enabled = True
    await session.commit()

    return MFARegisterResponse(
        secret=secret,
        uri=get_mfa_uri(secret, user.email),
    )


@router.post("/mfa/disable")
async def disable_mfa(body: MFAVerifyRequest, current_user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.id == current_user.get("sub")))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA not configured")

    if not verify_mfa_code(user.mfa_secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    user.mfa_enabled = False
    user.mfa_secret = None
    await session.commit()
    return {"message": "MFA disabled successfully"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.id == current_user.get("sub")))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/change-password")
async def change_password(
    body: PasswordChangeRequest,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(User).where(User.id == current_user.get("sub")))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    user.password_hash = hash_password(body.new_password)
    await session.commit()
    return {"message": "Password changed successfully"}


async def _generate_token_response(user: User) -> LoginResponse:
    access_token = create_access_token({
        "sub": str(user.id),
        "org_id": str(user.org_id) if user.org_id else None,
        "role": user.role,
        "permissions": user.permissions or [],
    })
    refresh_token_str = create_refresh_token({"sub": str(user.id)})

    # Store hashed refresh token
    token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
    # In production, store via dependency injection
    # For now, return without persisting (would need session)
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
