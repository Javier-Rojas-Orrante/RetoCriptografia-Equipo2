import base64
import binascii
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import engine
from app.models import AuditLog, Permission, Role, RolePermission, SystemSecret, User

ROLE_DEFINITIONS = {
    "ADMIN": {
        "name": "Administrador",
        "permissions": [
            ("users", "create"),
            ("users", "view"),
            ("users", "activate"),
            ("users", "revoke"),
            ("users", "change_role"),
            ("users", "change_expiration"),
            ("audit", "view"),
            ("admin_recovery", "activate"),
            ("certificates", "view"),
        ],
    },
    "COORDINADOR": {
        "name": "Coordinador",
        "permissions": [
            ("documents", "view"),
            ("documents", "edit"),
            ("operations", "view"),
        ],
    },
    "OPERATIVO": {
        "name": "Operativo",
        "permissions": [
            ("documents", "view"),
            ("operations", "view"),
            ("operations", "edit"),
        ],
    },
    "VOLUNTARIO": {
        "name": "Voluntario",
        "permissions": [("documents", "view")],
    },
}

VISIBLE_ROLE_CODES = tuple(ROLE_DEFINITIONS)
CRYPTO_ROLE_CODES = {"ADMIN", "COORDINADOR"}
DEFAULT_CRYPTO_VALIDITY_DAYS = 365
DEFAULT_PASSWORD = "demo1234"
DEMO_ADMIN_PASSWORD = "admin"
DEMO_BACKUP_ADMIN_PASSWORD = "respaldo1234"
OLD_ROLE_MAP = {
    "ADMIN": "ADMIN",
    "COORDINADOR": "COORDINADOR",
    "OPERATIVO": "OPERATIVO",
    "VOLUNTARIO": "VOLUNTARIO",
    "HUMANITARIA": "COORDINADOR",
    "LEGAL_TI": "COORDINADOR",
    "LECTURA": "OPERATIVO",
    "EXTERNAL": "VOLUNTARIO",
}

DEMO_USERS = [
    {
        "full_name": "Admin Demo",
        "email": "admin@demo.local",
        "role_code": "ADMIN",
        "status": "active",
        "password": DEMO_ADMIN_PASSWORD,
    },
    {
        "full_name": "Cora Coordinadora",
        "email": "coordinador@demo.local",
        "role_code": "COORDINADOR",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Omar Operativo",
        "email": "operativo@demo.local",
        "role_code": "OPERATIVO",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Vale Voluntaria",
        "email": "voluntario@demo.local",
        "role_code": "VOLUNTARIO",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
]


def role_requires_crypto(role_or_user) -> bool:
    role = getattr(role_or_user, "role", role_or_user)
    return bool(role and getattr(role, "code", None) in CRYPTO_ROLE_CODES)


def _normalized_future_datetime(value: datetime) -> datetime:
    clean_value = value.replace(microsecond=0)
    if clean_value <= datetime.utcnow():
        raise ValueError("La fecha de expiracion debe ser futura")
    return clean_value


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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


def _role_order(role: Role) -> int:
    return list(ROLE_DEFINITIONS).index(role.code) if role.code in ROLE_DEFINITIONS else len(ROLE_DEFINITIONS)


def _demo_secret_for_user(user: User) -> str:
    if user.is_backup_admin:
        return DEMO_BACKUP_ADMIN_PASSWORD
    if user.email == "admin@demo.local":
        return DEMO_ADMIN_PASSWORD
    return DEFAULT_PASSWORD


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


class PasswordService:
    iterations = 120_000

    @classmethod
    def hash_password(cls, password: str) -> str:
        if not password.strip():
            raise ValueError("Debes indicar una contrasena")

        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, cls.iterations)
        return "pbkdf2_sha256${}${}${}".format(
            cls.iterations,
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )

    @staticmethod
    def verify_password(password: str, password_hash: str | None) -> bool:
        if not password_hash:
            return False

        try:
            algorithm, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            expected = base64.b64decode(digest_text.encode())
            salt = base64.b64decode(salt_text.encode())
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations_text))
        except (binascii.Error, ValueError, TypeError):
            return False

        return hmac.compare_digest(actual, expected)


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
            "p12_base64": "TEXT",
            "password_hash": "VARCHAR(255)",
            "is_backup_admin": "BOOLEAN NOT NULL DEFAULT 0",
            "mirror_source_user_id": "INTEGER",
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
    ca_key_secret = "ca_private_key_pem"
    ca_cert_secret = "ca_certificate_pem"

    @classmethod
    def _set_secret(cls, db: Session, key: str, value: str) -> None:
        secret = db.scalar(select(SystemSecret).where(SystemSecret.key == key).limit(1))
        if secret:
            secret.value_text = value
            secret.updated_at = datetime.utcnow()
        else:
            db.add(SystemSecret(key=key, value_text=value))
        db.commit()

    @classmethod
    def _get_secret(cls, db: Session, key: str) -> str | None:
        secret = db.scalar(select(SystemSecret).where(SystemSecret.key == key).limit(1))
        return secret.value_text if secret else None

    @classmethod
    def ensure_ca(cls, db: Session) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key_pem = cls._get_secret(db, cls.ca_key_secret)
        cert_pem = cls._get_secret(db, cls.ca_cert_secret)
        if key_pem and cert_pem:
            private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            certificate = x509.load_pem_x509_certificate(cert_pem.encode())
            return private_key, certificate

        cls.ca_dir.mkdir(parents=True, exist_ok=True)
        cls.user_dir.mkdir(parents=True, exist_ok=True)
        if cls.ca_key_path.exists() and cls.ca_cert_path.exists():
            key_pem = cls.ca_key_path.read_text()
            cert_pem = cls.ca_cert_path.read_text()
            cls._set_secret(db, cls.ca_key_secret, key_pem)
            cls._set_secret(db, cls.ca_cert_secret, cert_pem)
            private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            certificate = x509.load_pem_x509_certificate(cert_pem.encode())
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
            .sign(private_key=private_key, algorithm=hashes.SHA256())
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        cls._set_secret(db, cls.ca_key_secret, private_key_pem.decode())
        cls._set_secret(db, cls.ca_cert_secret, certificate_pem.decode())
        return private_key, certificate

    @classmethod
    def get_ca_certificate_pem(cls, db: Session) -> str:
        _, certificate = cls.ensure_ca(db)
        return certificate.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def describe_ca_certificate(cls, db: Session) -> dict:
        _, certificate = cls.ensure_ca(db)
        return _certificate_summary(
            certificate,
            certificate.public_bytes(serialization.Encoding.PEM).decode(),
        )


class CertificateService:
    @staticmethod
    def issue_for_user(db: Session, user: User, password: str, reissue: bool = False) -> User:
        if not role_requires_crypto(user):
            raise ValueError("Este usuario no requiere certificado criptografico")
        if not password.strip():
            raise ValueError("Debes indicar una contrasena para el archivo .p12")
        if (user.p12_base64 or user.p12_path) and not reissue and user.certificate_serial:
            return user

        ca_key, ca_cert = CertificateAuthorityService.ensure_ca(db)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        if user.end_date is None:
            user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(microsecond=0)
        user.end_date = _normalized_future_datetime(user.end_date)
        valid_until = _as_utc(user.end_date)

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
            .not_valid_after(valid_until)
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

        user.certificate_serial = format(certificate.serial_number, "x")
        user.certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        user.certificate_not_before = certificate.not_valid_before_utc.replace(tzinfo=None)
        user.certificate_not_after = certificate.not_valid_after_utc.replace(tzinfo=None)
        user.p12_base64 = base64.b64encode(p12_bytes).decode()
        user.p12_path = None
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def get_user_p12_bytes(db: Session, user: User) -> bytes | None:
        if user.p12_base64:
            return base64.b64decode(user.p12_base64.encode())
        if user.p12_path:
            p12_path = Path(user.p12_path)
            if p12_path.exists():
                p12_bytes = p12_path.read_bytes()
                user.p12_base64 = base64.b64encode(p12_bytes).decode()
                user.p12_path = None
                user.updated_at = datetime.utcnow()
                db.commit()
                db.refresh(user)
                return p12_bytes
        return None

    @staticmethod
    def migrate_existing_crypto_material(db: Session) -> int:
        migrated = 0
        CertificateAuthorityService.ensure_ca(db)
        users = list(db.scalars(select(User).options(joinedload(User.role))).all())
        for user in users:
            if user.p12_base64:
                continue
            if not user.p12_path:
                continue
            p12_path = Path(user.p12_path)
            if not p12_path.exists():
                continue
            user.p12_base64 = base64.b64encode(p12_path.read_bytes()).decode()
            user.p12_path = None
            user.updated_at = datetime.utcnow()
            migrated += 1
        if migrated:
            db.commit()
        return migrated

    @staticmethod
    def describe_user_certificate(user: User) -> dict | None:
        if not user.certificate_pem:
            return None
        certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
        return _certificate_summary(certificate, user.certificate_pem)


class SignatureLoginService:
    @staticmethod
    def _certificate_has_user_email(certificate: x509.Certificate, email: str) -> bool:
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            if email in san.value.get_values_for_type(x509.RFC822Name):
                return True
        except x509.ExtensionNotFound:
            pass

        subject_emails = certificate.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        return any(attribute.value == email for attribute in subject_emails)

    @staticmethod
    def _verify_ca_signature(certificate: x509.Certificate, ca_certificate: x509.Certificate) -> None:
        ca_public_key = ca_certificate.public_key()
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            raise ValueError("La CA interna no usa una llave RSA valida")

        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )

    @staticmethod
    def authenticate_with_p12(db: Session, *, identifier: str, p12_bytes: bytes, password: str) -> tuple[User, dict]:
        user = PasswordLoginService.find_user_by_identifier(db, identifier)
        if not user:
            raise ValueError("Usuario no registrado")
        if user.status != "active":
            raise ValueError(f"La cuenta no esta activa: {user.status}")
        if not role_requires_crypto(user):
            raise ValueError("Este usuario entra con correo y contrasena")
        if not user.certificate_serial:
            raise ValueError("El usuario no tiene certificado emitido")

        try:
            private_key, certificate, _extra = pkcs12.load_key_and_certificates(
                p12_bytes,
                password.encode(),
            )
        except Exception as exc:
            raise ValueError("No se pudo abrir el .p12 con esa contrasena") from exc

        if private_key is None or certificate is None:
            raise ValueError("El .p12 no contiene llave privada y certificado")
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("El .p12 no contiene una llave privada RSA")
        if not isinstance(certificate.public_key(), rsa.RSAPublicKey):
            raise ValueError("El certificado no contiene una llave publica RSA")

        if format(certificate.serial_number, "x") != user.certificate_serial:
            raise ValueError("El certificado no corresponde al usuario registrado")
        if not SignatureLoginService._certificate_has_user_email(certificate, user.email):
            raise ValueError("El correo del certificado no coincide con el usuario")

        now = datetime.now(UTC)
        if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
            raise ValueError("El certificado esta fuera de vigencia")
        if user.end_date:
            if certificate.not_valid_after_utc.replace(tzinfo=None) != user.end_date.replace(microsecond=0):
                raise ValueError("El certificado no coincide con la vigencia actual del usuario")

        _ca_key, ca_certificate = CertificateAuthorityService.ensure_ca(db)
        try:
            SignatureLoginService._verify_ca_signature(certificate, ca_certificate)
        except InvalidSignature as exc:
            raise ValueError("La CA interna no reconoce la firma del certificado") from exc

        challenge = f"login:{user.id}:{user.email}:{now.isoformat()}".encode()
        signature = private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        certificate.public_key().verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        proof = {
            "challenge": challenge.decode(),
            "signature_preview": signature.hex()[:48],
            "signature_algorithm": "RSA-PSS-SHA256",
            "certificate_signature_algorithm": certificate.signature_algorithm_oid._name,
        }
        return user, proof


class ExpirationService:
    @staticmethod
    def expire_users(db: Session) -> int:
        users = list(
            db.scalars(
                select(User).where(
                    User.status == "active",
                    User.is_backup_admin.is_(False),
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


class AdminRecoveryService:
    backup_email = "admin.respaldo@demo.local"

    @staticmethod
    def get_primary_admin(db: Session) -> User | None:
        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .join(Role)
            .where(Role.code == "ADMIN", User.is_backup_admin.is_(False))
            .order_by(User.id.asc())
            .limit(1)
        )

    @staticmethod
    def get_active_admin(db: Session) -> User | None:
        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .join(Role)
            .where(Role.code == "ADMIN", User.status == "active")
            .order_by(User.is_backup_admin.asc(), User.id.asc())
            .limit(1)
        )

    @staticmethod
    def get_backup_admin(db: Session) -> User | None:
        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .where(User.is_backup_admin.is_(True))
            .order_by(User.id.asc())
            .limit(1)
        )

    @classmethod
    def sync_backup_admin(cls, db: Session) -> User | None:
        primary = cls.get_primary_admin(db)
        if not primary:
            return None

        backup = cls.get_backup_admin(db)
        if not backup:
            admin_role = primary.role
            candidate_email = cls.backup_email
            if db.scalar(select(User).where(User.email == candidate_email)):
                candidate_email = f"admin.respaldo.{primary.id}@demo.local"
            backup = User(
                full_name=f"{primary.full_name} Respaldo",
                email=candidate_email,
                role_id=admin_role.id,
                status="revoked",
                password_hash=PasswordService.hash_password(DEMO_BACKUP_ADMIN_PASSWORD),
                is_backup_admin=True,
                mirror_source_user_id=primary.id,
                end_date=primary.end_date,
            )
            db.add(backup)
            db.flush()
            backup.role = admin_role
            return backup

        if backup.status == "revoked":
            backup.full_name = f"{primary.full_name} Respaldo"
            backup.role_id = primary.role_id
            backup.role = primary.role
            backup.mirror_source_user_id = primary.id
            backup.end_date = primary.end_date
            backup.updated_at = datetime.utcnow()
            if not backup.password_hash:
                backup.password_hash = PasswordService.hash_password(DEMO_BACKUP_ADMIN_PASSWORD)

        if role_requires_crypto(backup) and (
            not backup.certificate_serial
            or not backup.certificate_not_after
            or (backup.end_date and backup.certificate_not_after.replace(microsecond=0) != backup.end_date.replace(microsecond=0))
        ):
            CertificateService.issue_for_user(db, backup, DEMO_BACKUP_ADMIN_PASSWORD, reissue=True)
        return backup

    @classmethod
    def activate_mirror(cls, db: Session, actor: User) -> tuple[User, User]:
        if actor.role.code != "ADMIN" or actor.status != "active" or actor.is_backup_admin:
            raise ValueError("Solo el administrador principal activo puede activar el espejo")

        backup = cls.get_backup_admin(db)
        if not backup:
            raise ValueError("No existe un administrador espejo configurado")
        if backup.status == "active":
            raise ValueError("El administrador espejo ya esta activo")

        actor.status = "revoked"
        actor.password_hash = None
        actor.updated_at = datetime.utcnow()

        backup.status = "active"
        backup.updated_at = datetime.utcnow()
        if not backup.password_hash:
            backup.password_hash = PasswordService.hash_password(DEMO_BACKUP_ADMIN_PASSWORD)

        db.commit()
        db.refresh(actor)
        db.refresh(backup)
        return actor, backup


class PasswordLoginService:
    @staticmethod
    def find_user_by_identifier(db: Session, identifier: str) -> User | None:
        clean_identifier = identifier.strip().lower()
        if not clean_identifier:
            return None

        if "@" in clean_identifier:
            return db.scalar(
                select(User)
                .options(joinedload(User.role))
                .where(User.email == clean_identifier)
                .limit(1)
            )

        if clean_identifier == "admin":
            primary = AdminRecoveryService.get_primary_admin(db)
            if primary and primary.status == "active":
                return primary
            active_admin = AdminRecoveryService.get_active_admin(db)
            if active_admin:
                return active_admin

        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .where(User.email.like(f"{clean_identifier}@%"))
            .order_by(User.id.asc())
            .limit(1)
        )

    @classmethod
    def authenticate_user(cls, db: Session, *, identifier: str, password: str) -> User:
        clean_identifier = identifier.strip().lower()
        user = cls.find_user_by_identifier(db, clean_identifier)
        if not user:
            raise ValueError("Usuario no registrado")
        if user.status != "active":
            raise ValueError(f"La cuenta no esta activa: {user.status}")
        if role_requires_crypto(user):
            raise ValueError("Este usuario requiere autenticacion con certificado .p12")
        if not PasswordService.verify_password(password, user.password_hash):
            raise ValueError("Contrasena incorrecta")
        return user


class BootstrapService:
    @staticmethod
    def _upsert_roles_and_permissions(db: Session) -> None:
        role_by_code = {role.code: role for role in db.scalars(select(Role)).all()}
        permission_by_key = {
            (permission.resource, permission.action): permission
            for permission in db.scalars(select(Permission)).all()
        }

        for code, config in ROLE_DEFINITIONS.items():
            role = role_by_code.get(code)
            if role:
                role.name = config["name"]
            else:
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

        current_role_permissions = {
            (role_permission.role_id, role_permission.permission_id)
            for role_permission in db.scalars(select(RolePermission)).all()
        }
        for code, config in ROLE_DEFINITIONS.items():
            role = role_by_code[code]
            for resource, action in config["permissions"]:
                permission = permission_by_key[(resource, action)]
                key = (role.id, permission.id)
                if key not in current_role_permissions:
                    db.add(RolePermission(role_id=role.id, permission_id=permission.id))
                    current_role_permissions.add(key)

    @staticmethod
    def _migrate_roles_and_passwords(db: Session) -> None:
        roles_by_code = {role.code: role for role in db.scalars(select(Role)).all()}
        fallback_role = roles_by_code["VOLUNTARIO"]

        for user in db.scalars(select(User).options(joinedload(User.role))).all():
            target_code = OLD_ROLE_MAP.get(user.role.code, fallback_role.code)
            target_role = roles_by_code[target_code]
            if user.role_id != target_role.id:
                user.role_id = target_role.id
                user.role = target_role

            if not user.password_hash:
                demo_password = (
                    DEMO_BACKUP_ADMIN_PASSWORD
                    if user.is_backup_admin
                    else DEMO_ADMIN_PASSWORD if user.email == "admin@demo.local" else DEFAULT_PASSWORD
                )
                user.password_hash = PasswordService.hash_password(demo_password)

            if role_requires_crypto(user) and user.end_date is None:
                user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(
                    microsecond=0
                )

    @staticmethod
    def _ensure_demo_users(db: Session) -> None:
        roles_by_code = {role.code: role for role in db.scalars(select(Role)).all()}
        for item in DEMO_USERS:
            user = db.scalar(select(User).where(User.email == item["email"]).limit(1))
            if user:
                if not user.password_hash:
                    user.password_hash = PasswordService.hash_password(item["password"])
                continue

            role = roles_by_code[item["role_code"]]
            end_date = (
                (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(microsecond=0)
                if role.code in CRYPTO_ROLE_CODES
                else None
            )
            db.add(
                User(
                    full_name=item["full_name"],
                    email=item["email"],
                    role_id=role.id,
                    status=item["status"],
                    end_date=end_date,
                    password_hash=PasswordService.hash_password(item["password"]),
                    is_backup_admin=False,
                )
            )
            db.flush()

    @staticmethod
    def seed(db: Session) -> None:
        SchemaService.ensure_user_certificate_columns()
        CertificateAuthorityService.ensure_ca(db)
        BootstrapService._upsert_roles_and_permissions(db)
        db.commit()

        BootstrapService._migrate_roles_and_passwords(db)
        BootstrapService._ensure_demo_users(db)
        CertificateService.migrate_existing_crypto_material(db)
        backup = AdminRecoveryService.sync_backup_admin(db)
        primary_admin = AdminRecoveryService.get_primary_admin(db)
        if primary_admin and not AdminRecoveryService.get_active_admin(db):
            primary_admin.status = "active"
            primary_admin.updated_at = datetime.utcnow()
            if not primary_admin.password_hash:
                primary_admin.password_hash = PasswordService.hash_password(DEMO_ADMIN_PASSWORD)
            if backup:
                backup.status = "revoked"
                backup.updated_at = datetime.utcnow()
        db.commit()
        ExpirationService.expire_users(db)

        for user in db.scalars(select(User).options(joinedload(User.role))).all():
            if not role_requires_crypto(user) or user.certificate_serial:
                continue
            if user.end_date is not None and user.end_date <= datetime.utcnow():
                if user.status != "expired":
                    user.status = "expired"
                    user.updated_at = datetime.utcnow()
                continue
            if user.end_date is None:
                user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(
                    microsecond=0
                )
                db.commit()
                db.refresh(user)
            if user.status in {"active", "pending", "revoked"}:
                CertificateService.issue_for_user(db, user, _demo_secret_for_user(user))
        if (
            backup
            and role_requires_crypto(backup)
            and not backup.certificate_serial
            and backup.end_date
            and backup.end_date > datetime.utcnow()
        ):
            CertificateService.issue_for_user(db, backup, _demo_secret_for_user(backup))
        db.commit()


class UserService:
    @staticmethod
    def create_user(
        db: Session,
        *,
        email: str,
        full_name: str,
        role_id: int,
        end_date: datetime | None = None,
        credential_secret: str,
    ) -> User:
        clean_email = email.strip().lower()
        clean_name = full_name.strip()
        if not clean_name:
            raise ValueError("Debes indicar el nombre completo")
        if db.scalar(select(User).where(User.email == clean_email)):
            raise ValueError("Ya existe un usuario con ese correo")

        role = db.get(Role, role_id)
        if not role or role.code not in VISIBLE_ROLE_CODES:
            raise ValueError("Rol no valido")

        clean_end_date = None
        if end_date is not None:
            clean_end_date = _normalized_future_datetime(end_date)
        elif role.code in CRYPTO_ROLE_CODES:
            clean_end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(microsecond=0)

        user = User(
            email=clean_email,
            full_name=clean_name,
            role_id=role_id,
            status="pending",
            end_date=clean_end_date,
            password_hash=PasswordService.hash_password(credential_secret),
            is_backup_admin=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        if role_requires_crypto(user):
            return CertificateService.issue_for_user(db, user, credential_secret)
        return user

    @staticmethod
    def get_user(db: Session, user_id: int) -> User | None:
        return db.scalar(select(User).options(joinedload(User.role)).where(User.id == user_id))

    @staticmethod
    def list_users(db: Session) -> list[User]:
        ExpirationService.expire_users(db)
        return list(
            db.scalars(
                select(User)
                .options(joinedload(User.role))
                .where(User.is_backup_admin.is_(False))
                .order_by(User.id.desc())
            ).all()
        )

    @staticmethod
    def list_certificate_history(db: Session) -> list[User]:
        return list(
            db.scalars(
                select(User)
                .options(joinedload(User.role))
                .where(User.is_backup_admin.is_(False), User.certificate_serial.is_not(None))
                .order_by(User.full_name.asc())
            ).all()
        )

    @staticmethod
    def get_actor(db: Session, actor_id: int | None = None) -> User | None:
        ExpirationService.expire_users(db)
        if actor_id is not None:
            return UserService.get_user(db, actor_id)

        actor = AdminRecoveryService.get_active_admin(db)
        if actor:
            return actor

        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .where(User.is_backup_admin.is_(False))
            .order_by(User.id.asc())
            .limit(1)
        )

    @staticmethod
    def list_roles(db: Session) -> list[Role]:
        roles = list(db.scalars(select(Role).where(Role.code.in_(VISIBLE_ROLE_CODES))).all())
        return sorted(roles, key=_role_order)

    @staticmethod
    def update_status(db: Session, user: User, status: str, new_secret: str = "") -> User:
        if status == "active":
            if user.end_date and user.end_date <= datetime.utcnow():
                raise ValueError("Actualiza la fecha de expiracion antes de activar esta cuenta")
            if role_requires_crypto(user):
                needs_reissue = user.status == "revoked" or not user.certificate_serial
                if needs_reissue:
                    if not new_secret.strip():
                        raise ValueError("Debes definir una nueva contrasena para el .p12")
                    user.password_hash = PasswordService.hash_password(new_secret)
                elif new_secret.strip():
                    user.password_hash = PasswordService.hash_password(new_secret)
            else:
                if not user.password_hash:
                    if not new_secret.strip():
                        raise ValueError("Debes definir una nueva contrasena para restablecer el acceso")
                    user.password_hash = PasswordService.hash_password(new_secret)
                elif new_secret.strip():
                    user.password_hash = PasswordService.hash_password(new_secret)
        elif status == "revoked":
            primary_admin = AdminRecoveryService.get_primary_admin(db)
            if primary_admin and primary_admin.id == user.id:
                raise ValueError("Usa la recuperacion por espejo para transferir al administrador principal")
            if role_requires_crypto(user):
                user.password_hash = None
            else:
                user.password_hash = None

        user.status = status
        user.updated_at = datetime.utcnow()
        AdminRecoveryService.sync_backup_admin(db)
        db.commit()
        db.refresh(user)
        if status == "active" and role_requires_crypto(user) and (not user.certificate_serial or new_secret.strip()):
            return CertificateService.issue_for_user(db, user, new_secret or _demo_secret_for_user(user), reissue=True)
        return user

    @staticmethod
    def update_expiration(db: Session, user: User, end_date: datetime, new_secret: str = "") -> User:
        clean_end_date = _normalized_future_datetime(end_date)
        user.end_date = clean_end_date
        if user.status == "expired":
            user.status = "active"
        user.updated_at = datetime.utcnow()
        AdminRecoveryService.sync_backup_admin(db)
        db.commit()
        db.refresh(user)
        if role_requires_crypto(user):
            if not new_secret.strip():
                raise ValueError("Debes indicar una nueva contrasena para reemitir el .p12")
            user.password_hash = PasswordService.hash_password(new_secret)
            db.commit()
            db.refresh(user)
            return CertificateService.issue_for_user(db, user, new_secret, reissue=True)
        return user

    @staticmethod
    def change_role(db: Session, user: User, role_id: int, new_secret: str = "") -> User:
        role = db.get(Role, role_id)
        if not role or role.code not in VISIBLE_ROLE_CODES:
            raise ValueError("Rol no valido")
        if user.is_backup_admin:
            raise ValueError("El administrador espejo se gestiona desde el modulo de recuperacion")

        old_role_was_crypto = role_requires_crypto(user)
        user.role_id = role_id
        user.role = role
        if role.code in CRYPTO_ROLE_CODES and user.end_date is None:
            user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(microsecond=0)
        user.updated_at = datetime.utcnow()
        AdminRecoveryService.sync_backup_admin(db)
        db.commit()
        db.refresh(user)
        if role.code in CRYPTO_ROLE_CODES and not old_role_was_crypto:
            if not new_secret.strip():
                raise ValueError("Debes indicar la contrasena inicial del .p12 para este rol")
            user.password_hash = PasswordService.hash_password(new_secret)
            db.commit()
            db.refresh(user)
            return CertificateService.issue_for_user(db, user, new_secret, reissue=True)
        return user
