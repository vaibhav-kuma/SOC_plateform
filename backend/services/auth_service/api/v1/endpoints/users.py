from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.security import hash_password
from core.dependencies import get_current_user, require_permissions
from services.auth_service.models.schemas import (
    UserCreate, UserUpdate, UserResponse, UserCreateResponse,
    OrganizationCreate, OrganizationResponse,
)
from common.models.base import User, Organization

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    page: int = 1,
    page_size: int = 50,
    current_user: dict = Depends(require_permissions(["users:read"])),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(User).where(User.org_id == org_id).offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return result.scalars().all()


@router.post("", response_model=UserCreateResponse, status_code=201)
async def create_user(
    body: UserCreate,
    current_user: dict = Depends(require_permissions(["users:write"])),
    session: AsyncSession = Depends(get_session),
):
    existing = await session.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        org_id=current_user.get("org_id"),
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        role=body.role,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    return UserCreateResponse(
        id=user.id, email=user.email,
        full_name=user.full_name, role=user.role,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: dict = Depends(require_permissions(["users:read"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UserUpdate,
    current_user: dict = Depends(require_permissions(["users:write"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(user, field, value)

    await session.commit()
    await session.refresh(user)
    return user


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_permissions(["users:write"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    await session.commit()
