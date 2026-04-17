from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import engine
from app.models import AuditLog, Permission, Role, RolePermission, User

ROLE_DEFINITIONS = {
    "ADMIN": {
        "name": "Administrador",
        "permissions": [
            ("users", "create"),
            ("users", "view"),
            ("users", "activate"),
            ("users", "revoke"),
            ("users", "reactivate"),
            ("users", "change_role"),
            ("audit", "view"),
        ],
    },
    "HUMANITARIA": {
        "name": "Humanitaria",
        "permissions": [("records", "view"), ("records", "edit")],
    },
    "LEGAL_TI": {
        "name": "Legal TI",
        "permissions": [("documents", "view"), ("documents", "edit")],
    },
    "LECTURA": {
        "name": "Solo lectura",
        "permissions": [("records", "view"), ("documents", "view")],
    },
    "EXTERNAL": {
        "name": "Externo",
        "permissions": [("documents", "view")],
    },
}

DEMO_USERS = [
    {"full_name": "Admin Demo", "email": "admin@demo.local", "role_code": "ADMIN", "status": "active"},
    {"full_name": "Ana Humanitaria", "email": "humanitaria@demo.local", "role_code": "HUMANITARIA", "status": "active"},
    {"full_name": "Luis Externo", "email": "externo@demo.local", "role_code": "EXTERNAL", "status": "pending"},
]


def _name_to_text(name: x509.Name) -> str:
    parts = []
    for attribute in name:
        label = getattr(attribute.oid, "_name", None) or attribute.oid.dotted_string
        parts.append(f"{label}={attribute.value}")
    return ", ".join(parts)


def _certificate_summary(certificate: x509.Certificate, pem_text: str) -> dict:
    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_emails = san_extension.value.get_values_for_type(x509.RFC822Name)
    except x509.ExtensionNotFound:
        san_emails = []

    return {
        "subject": _name_to_text(certificate.subject),
        "issuer": _name_to_text(certificate.issuer),
        "serial": format(certificate.serial_number, "x"),
        "not_before": certificate.not_valid_before_utc.replace(tzinfo=None),
        "not_after": certificate.not_valid_after_utc.replace(tzinfo=None),
        "san_emails": san_emails,
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "pem": pem_text,
    }


class AuditService:
    @staticmethod
    def log(
        db: Session,
        *,
        event_type: str,
        action: str,
        result: str,
        actor_user_id: int | None = None,
        target_user_id: int | None = None,
        resource: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        db.add(
            AuditLog(
                event_type=event_type,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                action=action,
                resource=resource,
                result=result,
                metadata_json=metadata or {},
            )
        )
        db.commit()

    @staticmethod
    def list_recent(db: Session, limit: int = 20) -> list[AuditLog]:
        return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all())


class SchemaService:
    @staticmethod
    def ensure_user_certificate_columns() -> None:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return

        current_columns = {column["name"] for column in inspector.get_columns("users")}
        extra_columns = {
            "certificate_serial": "VARCHAR(128)",
            "certificate_pem": "TEXT",
            "certificate_not_before": "DATETIME",
            "certificate_not_after": "DATETIME",
            "p12_path": "VARCHAR(255)",
        }

        with engine.begin() as connection:
            for column_name, column_type in extra_columns.items():
                if column_name not in current_columns:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"))


class CertificateAuthorityService:
    base_dir = Path(settings.certs_dir)
    ca_dir = base_dir / "ca"
    user_dir = base_dir / "users"
    ca_key_path = ca_dir / "ca-key.pem"
    ca_cert_path = ca_dir / "ca-cert.pem"

    @classmethod
    def ensure_ca(cls) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        cls.ca_dir.mkdir(parents=True, exist_ok=True)
        cls.user_dir.mkdir(parents=True, exist_ok=True)

        if cls.ca_key_path.exists() and cls.ca_cert_path.exists():
            private_key = serialization.load_pem_private_key(cls.ca_key_path.read_bytes(), password=None)
            certificate = x509.load_pem_x509_certificate(cls.ca_cert_path.read_bytes())
            return private_key, certificate

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Casa Monarca Demo CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Casa Monarca Internal CA"),
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )

        cls.ca_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cls.ca_cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        return private_key, certificate

    @classmethod
    def get_ca_certificate_path(cls) -> Path:
        _, _ = cls.ensure_ca()
        return cls.ca_cert_path

    @classmethod
    def describe_ca_certificate(cls) -> dict:
        _, certificate = cls.ensure_ca()
        return _certificate_summary(
            certificate,
            certificate.public_bytes(serialization.Encoding.PEM).decode(),
        )


class CertificateService:
    @staticmethod
    def issue_for_user(db: Session, user: User, password: str, reissue: bool = False) -> User:
        if not password.strip():
            raise ValueError("Debes indicar una contrasena para el archivo .p12")
        if user.p12_path and not reissue:
            return user

        ca_key, ca_cert = CertificateAuthorityService.ensure_ca()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Casa Monarca"),
                x509.NameAttribute(NameOID.COMMON_NAME, user.full_name),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, user.email),
            ]
        )

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.EMAIL_PROTECTION]
                ),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(user.email)]), critical=False)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        p12_bytes = pkcs12.serialize_key_and_certificates(
            name=user.email.encode(),
            key=private_key,
            cert=certificate,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        )

        CertificateAuthorityService.user_dir.mkdir(parents=True, exist_ok=True)
        safe_email = user.email.replace("@", "_at_").replace(".", "_")
        p12_path = (CertificateAuthorityService.user_dir / f"user-{user.id}-{safe_email}.p12").resolve()
        p12_path.write_bytes(p12_bytes)

        user.certificate_serial = format(certificate.serial_number, "x")
        user.certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        user.certificate_not_before = certificate.not_valid_before_utc.replace(tzinfo=None)
        user.certificate_not_after = certificate.not_valid_after_utc.replace(tzinfo=None)
        user.p12_path = str(p12_path)
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def describe_user_certificate(user: User) -> dict | None:
        if not user.certificate_pem:
            return None
        certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
        return _certificate_summary(certificate, user.certificate_pem)


class BootstrapService:
    @staticmethod
    def seed(db: Session) -> None:
        SchemaService.ensure_user_certificate_columns()
        CertificateAuthorityService.ensure_ca()

        roles = list(db.scalars(select(Role)).all())
        if not roles:
            role_by_code: dict[str, Role] = {}
            permission_by_key: dict[tuple[str, str], Permission] = {}

            for code, config in ROLE_DEFINITIONS.items():
                role = Role(code=code, name=config["name"])
                db.add(role)
                db.flush()
                role_by_code[code] = role

            for config in ROLE_DEFINITIONS.values():
                for resource, action in config["permissions"]:
                    key = (resource, action)
                    if key not in permission_by_key:
                        permission = Permission(resource=resource, action=action)
                        db.add(permission)
                        db.flush()
                        permission_by_key[key] = permission

            for code, config in ROLE_DEFINITIONS.items():
                role = role_by_code[code]
                for resource, action in config["permissions"]:
                    db.add(
                        RolePermission(
                            role_id=role.id,
                            permission_id=permission_by_key[(resource, action)].id,
                        )
                    )

            db.commit()

        users = list(db.scalars(select(User)).all())
        if not users:
            roles_by_code = {role.code: role for role in db.scalars(select(Role)).all()}
            for item in DEMO_USERS:
                db.add(
                    User(
                        full_name=item["full_name"],
                        email=item["email"],
                        role_id=roles_by_code[item["role_code"]].id,
                        status=item["status"],
                    )
                )
            db.commit()


class ExpirationService:
    @staticmethod
    def expire_users(db: Session) -> int:
        users = list(
            db.scalars(
                select(User).where(
                    User.status == "active",
                    User.end_date.is_not(None),
                    User.end_date < datetime.utcnow(),
                )
            ).all()
        )

        for user in users:
            user.status = "expired"
            user.updated_at = datetime.utcnow()
            db.add(
                AuditLog(
                    event_type="user_expired",
                    actor_user_id=None,
                    target_user_id=user.id,
                    action="expire",
                    resource="users",
                    result="success",
                    metadata_json={},
                )
            )

        db.commit()
        return len(users)


class AuthorizationService:
    @staticmethod
    def get_permissions(db: Session, user: User) -> list[dict]:
        rows = db.execute(
            select(Permission.resource, Permission.action)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == user.role_id)
        ).all()
        return [{"resource": row.resource, "action": row.action} for row in rows]

    @staticmethod
    def authorize(db: Session, user: User | None, resource: str, action: str) -> bool:
        if not user or user.status != "active":
            return False
        return any(
            item["resource"] == resource and item["action"] == action
            for item in AuthorizationService.get_permissions(db, user)
        )


class UserService:
    @staticmethod
    def create_user(
        db: Session,
        *,
        email: str,
        full_name: str,
        role_id: int,
        end_date=None,
        p12_password: str,
    ) -> User:
        user = User(
            email=email.lower(),
            full_name=full_name,
            role_id=role_id,
            status="pending",
            end_date=end_date,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        try:
            return CertificateService.issue_for_user(db, user, p12_password)
        except Exception:
            db.delete(user)
            db.commit()
            raise

    @staticmethod
    def get_user(db: Session, user_id: int) -> User | None:
        return db.scalar(select(User).options(joinedload(User.role)).where(User.id == user_id))

    @staticmethod
    def list_users(db: Session) -> list[User]:
        ExpirationService.expire_users(db)
        return list(db.scalars(select(User).options(joinedload(User.role)).order_by(User.id.desc())).all())

    @staticmethod
    def get_actor(db: Session, actor_id: int | None = None) -> User | None:
        ExpirationService.expire_users(db)
        if actor_id is not None:
            return UserService.get_user(db, actor_id)
        actor = db.scalar(
            select(User).options(joinedload(User.role)).join(Role).where(Role.code == "ADMIN").limit(1)
        )
        if actor:
            return actor
        return db.scalar(select(User).options(joinedload(User.role)).limit(1))

    @staticmethod
    def list_roles(db: Session) -> list[Role]:
        return list(db.scalars(select(Role).order_by(Role.name.asc())).all())

    @staticmethod
    def update_status(db: Session, user: User, status: str) -> User:
        user.status = status
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def change_role(db: Session, user: User, role_id: int) -> User:
        user.role_id = role_id
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user
