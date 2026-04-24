from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RoleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    name: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role_id: int
    status: str
    certificate_serial: str | None
    certificate_not_before: datetime | None
    certificate_not_after: datetime | None
    is_backup_admin: bool
    mirror_source_user_id: int | None
    end_date: datetime | None
    created_at: datetime
    updated_at: datetime


class PermissionOut(BaseModel):
    resource: str
    action: str


class MeOut(BaseModel):
    user: UserOut
    role: RoleOut
    permissions: list[PermissionOut]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_type: str
    actor_user_id: int | None
    target_user_id: int | None
    action: str
    resource: str | None
    result: str
    metadata_json: dict | None
    created_at: datetime
