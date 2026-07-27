from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


class MessageResponse(BaseModel):
    message: str
    status: str = "success"


class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: UUID
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[Dict]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
