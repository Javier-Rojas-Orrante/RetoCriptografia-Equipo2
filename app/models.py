from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.crypto import EncryptedJSON, EncryptedText, database_crypto
from app.db import Base


class Beneficiario(Base):
    __tablename__ = "beneficiarios"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    nombre_completo: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    pais_origen: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    fecha_ingreso: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    area: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    area_lookup: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    status: Mapped[str] = mapped_column(EncryptedText(), nullable=False, default="nuevo")
    notas: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @validates("area")
    def _sync_area_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip()
        self.area_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    code_lookup: Mapped[str | None] = mapped_column(String(80), unique=True, index=True, nullable=True)
    name: Mapped[str] = mapped_column(EncryptedText(), nullable=False)

    @validates("code")
    def _sync_code_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip()
        self.code_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    email_lookup: Mapped[str | None] = mapped_column(String(80), unique=True, index=True, nullable=True)
    full_name: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    status: Mapped[str] = mapped_column(EncryptedText(), nullable=False, default="pending")
    status_lookup: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    certificate_serial: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    certificate_pem: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    public_key_pem: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    private_key_pem_encrypted: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    private_key_delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    certificate_not_before: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    certificate_not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    certificate_issuer_pem: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    certificate_issuer_user_id: Mapped[int | None] = mapped_column(nullable=True)
    password_hash: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    is_backup_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mirror_source_user_id: Mapped[int | None] = mapped_column(nullable=True)
    end_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    login_locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    role: Mapped[Role] = relationship()

    @validates("email")
    def _sync_email_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip().lower()
        self.email_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value

    @validates("status")
    def _sync_status_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip()
        self.status_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("resource", "action", name="uniq_permissions_resource_action"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    resource: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    action: Mapped[str] = mapped_column(EncryptedText(), nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="uniq_role_permissions"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(nullable=True)
    target_user_id: Mapped[int | None] = mapped_column(nullable=True)
    action: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    resource: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    result: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(EncryptedJSON(), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(EncryptedText(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)


class SystemSecret(Base):
    __tablename__ = "system_secrets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    key_lookup: Mapped[str | None] = mapped_column(String(80), unique=True, index=True, nullable=True)
    value_text: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    @validates("key")
    def _sync_key_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip()
        self.key_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    type_lookup: Mapped[str | None] = mapped_column(String(80), index=True, nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    title: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    message: Mapped[str] = mapped_column(EncryptedText(), nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(EncryptedJSON(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    @validates("type")
    def _sync_type_lookup(self, _key: str, value: str) -> str:
        clean_value = value.strip()
        self.type_lookup = database_crypto.lookup_digest(clean_value)
        return clean_value
