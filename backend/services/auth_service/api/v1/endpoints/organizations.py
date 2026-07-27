from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions
from services.auth_service.models.schemas import (
    OrganizationCreate, OrganizationResponse,
)
from common.models.base import Organization, User

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.post("", response_model=OrganizationResponse, status_code=201)
async def create_organization(
    body: OrganizationCreate,
    current_user: dict = Depends(require_permissions(["orgs:write"])),
    session: AsyncSession = Depends(get_session),
):
    existing = await session.execute(
        select(Organization).where(Organization.slug == body.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Organization slug already exists")

    org = Organization(name=body.name, slug=body.slug)
    session.add(org)
    await session.commit()
    await session.refresh(org)
    return org


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    current_user: dict = Depends(require_permissions(["orgs:read"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Organization))
    return result.scalars().all()


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org
