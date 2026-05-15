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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session, joinedload

from app.config import settings
from app.db import engine
from app.models import AuditLog, Beneficiario, Notification, Permission, Role, RolePermission, SystemSecret, User

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
            ("certificates", "view"),
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
        "full_name": "Coord. Administración",
        "email": "coord.administracion@demo.local",
        "role_code": "COORDINADOR",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Coord. Legal",
        "email": "coord.legal@demo.local",
        "role_code": "COORDINADOR",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Coord. Psicosocial",
        "email": "coord.psicosocial@demo.local",
        "role_code": "COORDINADOR",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Coord. Humanitario",
        "email": "coord.humanitario@demo.local",
        "role_code": "COORDINADOR",
        "status": "active",
        "password": DEFAULT_PASSWORD,
    },
    {
        "full_name": "Coord. Comunicación",
        "email": "coord.comunicacion@demo.local",
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
DEMO_USER_EMAILS = {item["email"] for item in DEMO_USERS}


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
        ip_address: str | None = None,
        user_agent: str | None = None,
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
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        db.commit()

    @staticmethod
    def list_recent(db: Session, limit: int = 20) -> list[AuditLog]:
        return list(db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all())


class NotificationService:
    MAX_LOGIN_ATTEMPTS = 10
    EXPIRY_WARNING_DAYS = 30

    @staticmethod
    def create(
        db: Session,
        *,
        type: str,
        title: str,
        message: str,
        user_id: int | None = None,
        metadata: dict | None = None,
    ) -> Notification:
        notif = Notification(
            type=type,
            user_id=user_id,
            title=title,
            message=message,
            metadata_json=metadata or {},
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)
        return notif

    @staticmethod
    def list_all(db: Session, limit: int = 50) -> list[Notification]:
        return list(db.scalars(select(Notification).order_by(Notification.id.desc()).limit(limit)).all())

    @staticmethod
    def list_unread(db: Session) -> list[Notification]:
        return list(db.scalars(select(Notification).where(Notification.is_read.is_(False)).order_by(Notification.id.desc())).all())

    @staticmethod
    def mark_read(db: Session, notification_id: int) -> None:
        notif = db.get(Notification, notification_id)
        if notif:
            notif.is_read = True
            db.commit()

    @staticmethod
    def mark_all_read(db: Session) -> None:
        for notif in db.scalars(select(Notification).where(Notification.is_read.is_(False))).all():
            notif.is_read = True
        db.commit()

    @staticmethod
    def check_expiring_certificates(db: Session) -> int:
        cutoff = datetime.utcnow() + timedelta(days=NotificationService.EXPIRY_WARNING_DAYS)
        users = list(
            db.scalars(
                select(User)
                .options(joinedload(User.role))
                .where(
                    User.status == "active",
                    User.certificate_not_after.is_not(None),
                    User.certificate_not_after <= cutoff,
                    User.certificate_not_after >= datetime.utcnow(),
                    User.is_backup_admin.is_(False),
                )
            ).all()
        )
        created = 0
        for user in users:
            # No crear duplicados: solo si no hay una de este tipo para este usuario en las últimas 24h
            existing = db.scalar(
                select(Notification).where(
                    Notification.type == "cert_expiring_soon",
                    Notification.user_id == user.id,
                    Notification.created_at >= datetime.utcnow() - timedelta(hours=24),
                ).limit(1)
            )
            if not existing:
                days_left = (user.certificate_not_after - datetime.utcnow()).days
                NotificationService.create(
                    db,
                    type="cert_expiring_soon",
                    title=f"Certificado próximo a vencer: {user.full_name}",
                    message=f"El certificado de {user.full_name} ({user.email}) vence en {days_left} días ({user.certificate_not_after.strftime('%Y-%m-%d')}). Revocar y re-emitir desde la sección Credencial.",
                    user_id=user.id,
                    metadata={"days_left": days_left, "expires": user.certificate_not_after.isoformat()},
                )
                created += 1
        return created

    @staticmethod
    def check_expiring_users(db: Session) -> int:
        """Create notifications for active users whose end_date is within 30 days."""
        cutoff = datetime.utcnow() + timedelta(days=NotificationService.EXPIRY_WARNING_DAYS)
        users = list(
            db.scalars(
                select(User)
                .options(joinedload(User.role))
                .where(
                    User.status == "active",
                    User.end_date.is_not(None),
                    User.end_date <= cutoff,
                    User.end_date >= datetime.utcnow(),
                    User.is_backup_admin.is_(False),
                )
            ).all()
        )
        created = 0
        for user in users:
            existing = db.scalar(
                select(Notification).where(
                    Notification.type == "user_expiring_soon",
                    Notification.user_id == user.id,
                    Notification.created_at >= datetime.utcnow() - timedelta(hours=24),
                ).limit(1)
            )
            if not existing:
                days_left = (user.end_date - datetime.utcnow()).days
                NotificationService.create(
                    db,
                    type="user_expiring_soon",
                    title=f"Usuario próximo a vencer: {user.full_name}",
                    message=(
                        f"La cuenta de {user.full_name} ({user.email}) expira en {days_left} día{'s' if days_left != 1 else ''} "
                        f"({user.end_date.strftime('%Y-%m-%d')}). Renueva o desactiva la cuenta desde la sección Usuarios."
                    ),
                    user_id=user.id,
                    metadata={"days_left": days_left, "expires": user.end_date.isoformat()},
                )
                created += 1
        return created


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

        dialect = engine.dialect.name
        datetime_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
        boolean_false_default = "BOOLEAN NOT NULL DEFAULT FALSE" if dialect == "postgresql" else "BOOLEAN NOT NULL DEFAULT 0"
        current_columns = {column["name"] for column in inspector.get_columns("users")}
        extra_columns = {
            "certificate_serial": "VARCHAR(128)",
            "certificate_pem": "TEXT",
            "public_key_pem": "TEXT",
            "private_key_pem_encrypted": "TEXT",
            "private_key_delivered_at": datetime_type,
            "certificate_not_before": datetime_type,
            "certificate_not_after": datetime_type,
            "certificate_issuer_pem": "TEXT",
            "certificate_issuer_user_id": "INTEGER",
            "password_hash": "VARCHAR(255)",
            "is_backup_admin": boolean_false_default,
            "mirror_source_user_id": "INTEGER",
            "login_attempts": "INTEGER NOT NULL DEFAULT 0",
            "login_locked_until": datetime_type,
        }

        with engine.begin() as connection:
            for column_name, column_type in extra_columns.items():
                if column_name not in current_columns:
                    connection.execute(text(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}"))

    @staticmethod
    def ensure_audit_log_columns() -> None:
        inspector = inspect(engine)
        if "audit_logs" not in inspector.get_table_names():
            return
        current_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
        extra_columns = {
            "ip_address": "VARCHAR(64)",
            "user_agent": "VARCHAR(255)",
        }
        with engine.begin() as connection:
            for column_name, column_type in extra_columns.items():
                if column_name not in current_columns:
                    connection.execute(text(f"ALTER TABLE audit_logs ADD COLUMN {column_name} {column_type}"))


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


class AdminSignerService:
    signer_key_prefix = "admin_signer_private_key_pem:"

    @classmethod
    def _secret_key(cls, user_id: int) -> str:
        return f"{cls.signer_key_prefix}{user_id}"

    @classmethod
    def store_private_key(cls, db: Session, user_id: int, private_key: rsa.RSAPrivateKey) -> None:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        CertificateAuthorityService._set_secret(db, cls._secret_key(user_id), private_key_pem)

    @classmethod
    def load_private_key(cls, db: Session, user_id: int) -> rsa.RSAPrivateKey | None:
        key_pem = CertificateAuthorityService._get_secret(db, cls._secret_key(user_id))
        if not key_pem:
            return None
        private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
        return private_key if isinstance(private_key, rsa.RSAPrivateKey) else None

    @staticmethod
    def get_active_signing_admin(db: Session) -> User | None:
        return db.scalar(
            select(User)
            .options(joinedload(User.role))
            .join(Role)
            .where(Role.code == "ADMIN", User.status == "active")
            .order_by(User.is_backup_admin.asc(), User.id.asc())
            .limit(1)
        )

    @classmethod
    def get_signing_material(cls, db: Session) -> tuple[User, rsa.RSAPrivateKey, x509.Certificate]:
        admin_user = cls.get_active_signing_admin(db)
        if not admin_user:
            raise ValueError("No existe un administrador activo para firmar certificados")
        if not admin_user.certificate_pem:
            raise ValueError("El administrador activo no tiene certificado emitido")

        private_key = cls.load_private_key(db, admin_user.id)
        if private_key is None:
            raise ValueError(
                "El administrador activo no tiene su llave privada centralizada. "
                "Reemite su certificado para continuar."
            )

        certificate = x509.load_pem_x509_certificate(admin_user.certificate_pem.encode())
        return admin_user, private_key, certificate

    @classmethod
    def get_active_signer_certificate_pem(cls, db: Session) -> str:
        admin_user = cls.get_active_signing_admin(db)
        if not admin_user or not admin_user.certificate_pem:
            raise ValueError("No existe un administrador firmante disponible")
        return admin_user.certificate_pem

    @classmethod
    def describe_active_signer_certificate(cls, db: Session) -> dict:
        pem_text = cls.get_active_signer_certificate_pem(db)
        certificate = x509.load_pem_x509_certificate(pem_text.encode())
        return _certificate_summary(certificate, pem_text)


class CertificateService:
    @staticmethod
    def _verify_self_signed_certificate(certificate: x509.Certificate) -> None:
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("El certificado no contiene una llave publica RSA")
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )

    @staticmethod
    def uses_current_signing_policy(user: User) -> bool:
        if not user.certificate_pem:
            return False

        certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
        if user.role and user.role.code == "ADMIN":
            if certificate.subject != certificate.issuer:
                return False
            try:
                CertificateService._verify_self_signed_certificate(certificate)
            except (InvalidSignature, ValueError):
                return False
            return True

        if user.role and user.role.code == "COORDINADOR":
            if certificate.subject == certificate.issuer or not user.certificate_issuer_pem:
                return False
            try:
                issuer_certificate = x509.load_pem_x509_certificate(user.certificate_issuer_pem.encode())
                CertificateService._verify_self_signed_certificate(issuer_certificate)
                SignatureLoginService._verify_ca_signature(certificate, issuer_certificate)
            except (InvalidSignature, ValueError):
                return False
            return True

        return True

    @staticmethod
    def issue_for_user(db: Session, user: User, password: str, reissue: bool = False) -> User:
        if not role_requires_crypto(user):
            raise ValueError("Este usuario no requiere certificado criptografico")
        if not password.strip():
            raise ValueError("Debes indicar una contrasena para el material criptografico")
        if user.certificate_serial and not reissue:
            return user

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

        issuer_user_id: int | None = None
        issuer_certificate: x509.Certificate | None = None
        if user.role and user.role.code == "ADMIN":
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
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
                .sign(private_key=private_key, algorithm=hashes.SHA256())
            )
            issuer_user_id = user.id
        else:
            signer_admin, signer_key, signer_certificate = AdminSignerService.get_signing_material(db)
            if signer_admin.id == user.id:
                raise ValueError("El administrador firmante no puede coincidir con el coordinador emitido")
            certificate = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(signer_certificate.subject)
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
                .sign(private_key=signer_key, algorithm=hashes.SHA256())
            )
            issuer_user_id = signer_admin.id
            issuer_certificate = signer_certificate

        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        private_key_pem_encrypted = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
        ).decode()
        user.certificate_serial = format(certificate.serial_number, "x")
        user.certificate_pem = certificate_pem
        user.public_key_pem = public_key_pem
        user.private_key_pem_encrypted = private_key_pem_encrypted
        user.private_key_delivered_at = None
        user.certificate_issuer_pem = (
            issuer_certificate.public_bytes(serialization.Encoding.PEM).decode()
            if issuer_certificate is not None
            else certificate_pem
        )
        user.certificate_issuer_user_id = issuer_user_id
        user.certificate_not_before = certificate.not_valid_before_utc.replace(tzinfo=None)
        user.certificate_not_after = certificate.not_valid_after_utc.replace(tzinfo=None)
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)

        if user.role and user.role.code == "ADMIN":
            AdminSignerService.store_private_key(db, user.id, private_key)

        return user

    @staticmethod
    def describe_user_certificate(user: User) -> dict | None:
        if not user.certificate_pem:
            return None
        certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
        return _certificate_summary(certificate, user.certificate_pem)

    @staticmethod
    def get_user_public_key_pem(user: User) -> str | None:
        if user.public_key_pem:
            return user.public_key_pem
        if not user.certificate_pem:
            return None
        certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            return None
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @staticmethod
    def get_user_private_key_pem(user: User) -> str | None:
        return user.private_key_pem_encrypted

    @staticmethod
    def private_key_download_available(user: User) -> bool:
        return bool(user.private_key_pem_encrypted and user.private_key_delivered_at is None)

    @staticmethod
    def deliver_user_private_key(db: Session, user: User) -> str:
        if not CertificateService.private_key_download_available(user):
            raise ValueError("La llave privada ya fue entregada. Debes reemitir la credencial para generar una nueva.")

        private_key_pem = user.private_key_pem_encrypted
        if not private_key_pem:
            raise ValueError("La llave privada no esta disponible para descarga")

        user.private_key_delivered_at = datetime.utcnow()
        user.private_key_pem_encrypted = None
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return private_key_pem

    @staticmethod
    def describe_crypto_material(user: User, issuer_name: str | None = None) -> dict | None:
        if not role_requires_crypto(user):
            return None

        signature_algorithm = "N/D"
        key_algorithm = "RSA 2048"
        if user.certificate_pem:
            certificate = x509.load_pem_x509_certificate(user.certificate_pem.encode())
            signature_algorithm = certificate.signature_algorithm_oid._name or "sha256WithRSAEncryption"
            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_algorithm = f"RSA {public_key.key_size}"

        if user.role and user.role.code == "ADMIN":
            signed_by = "Autofirmado"
            signed_with = "private_key.pem propia"
            signer_verified_with = "public_key.pem propia"
        else:
            signed_by = issuer_name or "Administrador firmante"
            signed_with = "private_key.pem del administrador firmante"
            signer_verified_with = f"public_key.pem de {issuer_name or 'administrador firmante'}"

        return {
            "has_certificate": bool(user.certificate_pem),
            "has_public_key": bool(CertificateService.get_user_public_key_pem(user)),
            "has_private_key": CertificateService.private_key_download_available(user),
            "private_key_delivered": bool(user.private_key_delivered_at),
            "serial": user.certificate_serial,
            "key_algorithm": key_algorithm,
            "certificate_signature_algorithm": signature_algorithm,
            "signed_by": signed_by,
            "signed_with": signed_with,
            "signer_verified_with": signer_verified_with,
            "login_artifact": "private_key.pem + certificate.pem + contrasena",
            "challenge_signed_with": "private_key.pem del usuario",
            "challenge_verified_with": "public_key.pem del certificado del usuario",
        }


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
            raise ValueError("El certificado emisor no usa una llave RSA valida")

        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )

    @staticmethod
    def _validate_certificate_for_user(db: Session, user: User, certificate: x509.Certificate) -> tuple[datetime, str]:
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

        if user.role.code == "ADMIN":
            if certificate.subject != certificate.issuer:
                raise ValueError("El certificado del administrador debe ser autofirmado")
            try:
                CertificateService._verify_self_signed_certificate(certificate)
            except InvalidSignature as exc:
                raise ValueError("La autofirma del certificado del administrador no es valida") from exc
            issuer_label = "Autofirmado"
        else:
            if certificate.subject == certificate.issuer:
                raise ValueError("Los certificados de coordinador no deben ser autofirmados")
            if user.certificate_issuer_pem:
                issuer_certificate = x509.load_pem_x509_certificate(user.certificate_issuer_pem.encode())
                try:
                    CertificateService._verify_self_signed_certificate(issuer_certificate)
                except InvalidSignature as exc:
                    raise ValueError("El certificado del administrador firmante no es valido") from exc
                try:
                    SignatureLoginService._verify_ca_signature(certificate, issuer_certificate)
                except InvalidSignature as exc:
                    raise ValueError("El certificado no fue firmado por el administrador registrado") from exc
                issuer_label = _name_to_text(issuer_certificate.subject)
            else:
                _ca_key, ca_certificate = CertificateAuthorityService.ensure_ca(db)
                try:
                    SignatureLoginService._verify_ca_signature(certificate, ca_certificate)
                except InvalidSignature as exc:
                    raise ValueError("La firma del certificado no coincide con el emisor esperado") from exc
                issuer_label = _name_to_text(ca_certificate.subject)

        return now, issuer_label

    @staticmethod
    def _build_login_proof(
        user: User,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        now: datetime,
        *,
        login_artifact: str,
        issuer_label: str,
    ) -> dict:
        challenge = f"login:{user.id}:{user.email}:{now.isoformat()}".encode()
        signature = private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        try:
            certificate.public_key().verify(
                signature,
                challenge,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature as exc:
            raise ValueError("La llave privada no corresponde al certificate.pem entregado") from exc

        return {
            "challenge": challenge.decode(),
            "signature_preview": signature.hex()[:48],
            "signature_algorithm": "RSA-PSS-SHA256",
            "certificate_signature_algorithm": certificate.signature_algorithm_oid._name,
            "login_artifact": login_artifact,
            "challenge_verified_with": "certificate public key",
            "issuer": issuer_label,
        }

    @staticmethod
    def authenticate_with_private_key_and_certificate(
        db: Session,
        *,
        identifier: str,
        private_key_bytes: bytes,
        certificate_bytes: bytes,
        password: str,
    ) -> tuple[User, dict]:
        user = PasswordLoginService.find_user_by_identifier(db, identifier)
        if not user:
            raise ValueError("Usuario no registrado")
        if user.login_locked_until is not None:
            raise ValueError("Cuenta bloqueada por demasiados intentos fallidos. Contacta al administrador.")
        if user.status != "active":
            raise ValueError(f"La cuenta no esta activa: {user.status}")
        if not role_requires_crypto(user):
            raise ValueError("Este usuario entra con correo y contrasena")
        if not user.certificate_serial:
            raise ValueError("El usuario no tiene certificado emitido")

        try:
            certificate = x509.load_pem_x509_certificate(certificate_bytes)
        except Exception as exc:
            raise ValueError("No se pudo leer certificate.pem") from exc

        try:
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=password.encode() if password else None,
            )
        except Exception as exc:
            user.login_attempts = (user.login_attempts or 0) + 1
            if user.login_attempts >= NotificationService.MAX_LOGIN_ATTEMPTS:
                user.login_locked_until = datetime.utcnow()
                db.commit()
                NotificationService.create(
                    db,
                    type="login_blocked",
                    title=f"Cuenta bloqueada: {user.full_name}",
                    message=f"La cuenta de {user.full_name} ({user.email}) fue bloqueada tras {NotificationService.MAX_LOGIN_ATTEMPTS} intentos fallidos. Desbloquear desde Gestionar cuenta.",
                    user_id=user.id,
                    metadata={"attempts": user.login_attempts},
                )
                raise ValueError("Cuenta bloqueada por demasiados intentos fallidos. Contacta al administrador.") from exc
            db.commit()
            raise ValueError("No se pudo abrir private_key.pem con esa contrasena") from exc

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("private_key.pem no contiene una llave privada RSA")
        if not isinstance(certificate.public_key(), rsa.RSAPublicKey):
            raise ValueError("certificate.pem no contiene una llave publica RSA")

        now, issuer_label = SignatureLoginService._validate_certificate_for_user(db, user, certificate)
        proof = SignatureLoginService._build_login_proof(
            user,
            private_key,
            certificate,
            now,
            login_artifact="private_key.pem + certificate.pem",
            issuer_label=issuer_label,
        )
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
        if not settings.seed_demo_data:
            return None

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
            or not CertificateService.uses_current_signing_policy(backup)
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
        if user.login_locked_until is not None:
            raise ValueError("Cuenta bloqueada por demasiados intentos fallidos. Contacta al administrador.")
        if user.status != "active":
            raise ValueError(f"La cuenta no esta activa: {user.status}")
        if role_requires_crypto(user) and user.certificate_serial:
            raise ValueError("Este usuario requiere autenticacion con private_key.pem y certificate.pem")
        if not PasswordService.verify_password(password, user.password_hash):
            user.login_attempts = (user.login_attempts or 0) + 1
            if user.login_attempts >= NotificationService.MAX_LOGIN_ATTEMPTS:
                user.login_locked_until = datetime.utcnow()
                db.commit()
                NotificationService.create(
                    db,
                    type="login_blocked",
                    title=f"Cuenta bloqueada: {user.full_name}",
                    message=f"La cuenta de {user.full_name} ({user.email}) fue bloqueada tras {NotificationService.MAX_LOGIN_ATTEMPTS} intentos fallidos de inicio de sesión. Desbloquear manualmente desde Gestionar cuenta.",
                    user_id=user.id,
                    metadata={"attempts": user.login_attempts},
                )
                raise ValueError("Cuenta bloqueada por demasiados intentos fallidos. Contacta al administrador.")
            db.commit()
            remaining = NotificationService.MAX_LOGIN_ATTEMPTS - user.login_attempts
            raise ValueError(f"Contraseña incorrecta. {remaining} intentos restantes antes del bloqueo.")
        user.login_attempts = 0
        user.login_locked_until = None
        db.commit()
        return user


class BootstrapService:
    @staticmethod
    def _can_manage_demo_certificate(user: User) -> bool:
        return settings.seed_demo_data and (user.is_backup_admin or user.email in DEMO_USER_EMAILS)

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

            if settings.seed_demo_data and not user.password_hash and (user.is_backup_admin or user.email in DEMO_USER_EMAILS):
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
    def _ensure_bootstrap_admin(db: Session) -> User | None:
        email = settings.bootstrap_admin_email
        if not email:
            return None

        admin_role = db.scalar(select(Role).where(Role.code == "ADMIN").limit(1))
        if not admin_role:
            raise ValueError("No se pudo ubicar el rol ADMIN para inicializar el administrador")

        user = db.scalar(
            select(User)
            .options(joinedload(User.role))
            .where(User.email == email)
            .limit(1)
        )
        if user:
            if not user.role or user.role.code != "ADMIN":
                raise ValueError(
                    "BOOTSTRAP_ADMIN_EMAIL ya existe con un rol distinto a ADMIN. "
                    "Usa otro correo o corrige ese usuario antes de desplegar."
                )
            if user.status != "active":
                raise ValueError(
                    "BOOTSTRAP_ADMIN_EMAIL ya existe pero no esta activo. "
                    "Reactiva esa cuenta manualmente o define otro correo de bootstrap."
                )
            if user.end_date is None:
                user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(
                    microsecond=0
                )
            if not user.password_hash:
                if not settings.bootstrap_admin_password:
                    raise ValueError("BOOTSTRAP_ADMIN_PASSWORD es obligatorio para completar el acceso inicial")
                user.password_hash = PasswordService.hash_password(settings.bootstrap_admin_password)
            user.updated_at = datetime.utcnow()
            db.flush()
            return user

        if not settings.bootstrap_admin_password:
            raise ValueError("BOOTSTRAP_ADMIN_PASSWORD es obligatorio para crear el administrador inicial")

        user = User(
            full_name=settings.bootstrap_admin_full_name,
            email=email,
            role_id=admin_role.id,
            status="active",
            end_date=(datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(microsecond=0),
            password_hash=PasswordService.hash_password(settings.bootstrap_admin_password),
            is_backup_admin=False,
        )
        db.add(user)
        db.flush()
        user.role = admin_role
        return user

    @staticmethod
    def seed(db: Session) -> None:
        SchemaService.ensure_user_certificate_columns()
        SchemaService.ensure_audit_log_columns()
        CertificateAuthorityService.ensure_ca(db)
        BootstrapService._upsert_roles_and_permissions(db)
        db.commit()

        BootstrapService._migrate_roles_and_passwords(db)
        if settings.seed_demo_data:
            BootstrapService._ensure_demo_users(db)
        else:
            BootstrapService._ensure_bootstrap_admin(db)

        has_visible_user = db.scalar(select(User.id).where(User.is_backup_admin.is_(False)).limit(1))
        if not has_visible_user:
            raise ValueError(
                "No hay usuarios iniciales configurados. Define BOOTSTRAP_ADMIN_EMAIL y "
                "BOOTSTRAP_ADMIN_PASSWORD o activa SEED_DEMO_DATA."
            )

        backup = AdminRecoveryService.sync_backup_admin(db)
        if settings.seed_demo_data:
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
        if settings.seed_demo_data:
            BeneficiarioService.seed_demo(db)

        users = list(db.scalars(select(User).options(joinedload(User.role))).all())
        users.sort(key=lambda user: (0 if user.role.code == "ADMIN" else 1, user.id))
        for user in users:
            if not role_requires_crypto(user):
                continue
            can_auto_manage = BootstrapService._can_manage_demo_certificate(user)
            needs_issue = not user.certificate_serial
            needs_policy_refresh = can_auto_manage and user.certificate_serial and not CertificateService.uses_current_signing_policy(user)
            needs_artifact_refresh = (
                can_auto_manage
                and user.certificate_serial
                and not user.public_key_pem
            )
            if not needs_issue and not needs_policy_refresh and not needs_artifact_refresh:
                continue
            if user.end_date is not None and user.end_date <= datetime.utcnow():
                if user.status != "expired":
                    user.status = "expired"
                    user.updated_at = datetime.utcnow()
                continue
            if not can_auto_manage:
                continue
            if user.end_date is None:
                user.end_date = (datetime.utcnow() + timedelta(days=DEFAULT_CRYPTO_VALIDITY_DAYS)).replace(
                    microsecond=0
                )
                db.commit()
                db.refresh(user)
            if user.status in {"active", "pending", "revoked"}:
                CertificateService.issue_for_user(
                    db,
                    user,
                    _demo_secret_for_user(user),
                    reissue=needs_policy_refresh or needs_artifact_refresh,
                )
        db.commit()


class BeneficiarioService:
    AREAS = ["ADMINISTRACION", "LEGAL", "PSICOSOCIAL", "HUMANITARIO", "COMUNICACION"]
    STATUSES = ["nuevo", "en_revision", "canalizado", "activo"]

    @staticmethod
    def list_all(db: Session) -> list[Beneficiario]:
        return list(db.scalars(select(Beneficiario).order_by(Beneficiario.fecha_ingreso.desc())).all())

    @staticmethod
    def list_by_area(db: Session, area: str) -> list[Beneficiario]:
        return list(
            db.scalars(
                select(Beneficiario).where(Beneficiario.area == area).order_by(Beneficiario.fecha_ingreso.desc())
            ).all()
        )

    @staticmethod
    def create(
        db: Session,
        *,
        nombre_completo: str,
        pais_origen: str,
        area: str,
        notas: str | None = None,
        created_by_user_id: int | None = None,
    ) -> Beneficiario:
        b = Beneficiario(
            nombre_completo=nombre_completo.strip(),
            pais_origen=pais_origen.strip(),
            area=area,
            notas=notas,
            created_by_user_id=created_by_user_id,
            fecha_ingreso=datetime.utcnow(),
        )
        db.add(b)
        db.flush()
        return b

    @staticmethod
    def update_status(db: Session, beneficiario_id: int, new_status: str) -> Beneficiario:
        b = db.get(Beneficiario, beneficiario_id)
        if not b:
            raise ValueError("Beneficiario no encontrado")
        b.status = new_status
        b.updated_at = datetime.utcnow()
        db.flush()
        return b

    @staticmethod
    def delete(db: Session, beneficiario_id: int) -> None:
        b = db.get(Beneficiario, beneficiario_id)
        if not b:
            raise ValueError("Beneficiario no encontrado")
        db.delete(b)
        db.flush()

    @staticmethod
    def seed_demo(db: Session) -> None:
        if db.scalar(select(Beneficiario).limit(1)):
            return  # already seeded
        demo_records = [
            ("María Guadalupe Torres", "Honduras", "PSICOSOCIAL", "activo", "Llegó con familia. En proceso de regularización."),
            ("Carlos Enrique Fuentes", "El Salvador", "LEGAL", "en_revision", "Solicitud de asilo presentada, pendiente resolución."),
            ("Aisha Balde", "Guinea Conakry", "HUMANITARIO", "nuevo", "Recién llegada, evaluación inicial pendiente."),
            ("Roberto Díaz Pérez", "Venezuela", "ADMINISTRACION", "canalizado", "Canalizado a albergue temporal."),
            ("Esperanza Morales", "Guatemala", "PSICOSOCIAL", "activo", "Asistiendo a talleres de integración."),
            ("Yusuf Al-Hassan", "Siria", "LEGAL", "en_revision", "Documentación incompleta, en seguimiento."),
            ("Lucía Ramírez", "Nicaragua", "HUMANITARIO", "activo", "Beneficiaria de apoyo alimentario mensual."),
            ("Pedro Alvarado", "Honduras", "COMUNICACION", "canalizado", "Participando en programa de comunicación comunitaria."),
            ("Fatima Diallo", "Mali", "LEGAL", "nuevo", "Primera cita con asesor legal agendada."),
            ("Ana Patricia Soto", "El Salvador", "PSICOSOCIAL", "activo", "Atención psicológica semanal en curso."),
        ]
        for nombre, pais, area, status, notas in demo_records:
            db.add(Beneficiario(
                nombre_completo=nombre,
                pais_origen=pais,
                area=area,
                status=status,
                notas=notas,
                fecha_ingreso=datetime.utcnow() - timedelta(days=demo_records.index((nombre, pais, area, status, notas)) * 7),
            ))
        db.flush()


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
                        raise ValueError("Debes definir una nueva contrasena para el material criptografico")
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
        # Expiration changes are not allowed for crypto roles (ADMIN/COORDINADOR).
        # Their account end_date is tied to the X.509 certificate validity, which
        # is a cryptographic property fixed at issuance and cannot be modified
        # without re-issuing the certificate and invalidating existing signatures.
        if role_requires_crypto(user):
            raise ValueError(
                "No se puede modificar la vigencia de un usuario con certificado X.509. "
                "La fecha de expiracion esta sellada criptograficamente en el certificado. "
                "Si necesitas extender el acceso, revocar y re-emitir un nuevo certificado desde la seccion Credencial."
            )
        clean_end_date = _normalized_future_datetime(end_date)
        user.end_date = clean_end_date
        if user.status == "expired":
            user.status = "active"
        user.updated_at = datetime.utcnow()
        AdminRecoveryService.sync_backup_admin(db)
        db.commit()
        db.refresh(user)
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
                raise ValueError("Debes indicar la contrasena inicial del material criptografico para este rol")
            user.password_hash = PasswordService.hash_password(new_secret)
            db.commit()
            db.refresh(user)
            return CertificateService.issue_for_user(db, user, new_secret, reissue=True)
        return user

    @staticmethod
    def unlock_user(db: Session, user: User) -> User:
        user.login_attempts = 0
        user.login_locked_until = None
        user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(user)
        return user
