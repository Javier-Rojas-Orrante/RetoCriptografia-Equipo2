# Modulo de cifrado para la base de datos
# Usa Fernet (AES-128-CBC con HMAC) para encriptar campos sensibles
# y HMAC-SHA256 para generar digests de busqueda ciega (lookup)
import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.types import Text, TypeDecorator

from app.config import settings


class DatabaseCrypto:
    # Prefijos para identificar valores encriptados y digests en la BD
    token_prefix = "enc:v1:"
    lookup_prefix = "idx:v1:"

    def __init__(self, secret: str) -> None:
        # Derivamos dos claves separadas: una para cifrar y otra para lookups
        normalized_secret = secret.strip() or f"{settings.session_secret}:db-encryption"
        encryption_material = hashlib.sha256(f"{normalized_secret}:cipher".encode()).digest()
        lookup_material = hashlib.sha256(f"{normalized_secret}:lookup".encode()).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(encryption_material))
        self._lookup_key = lookup_material

    def is_encrypted(self, value: Any) -> bool:
        return isinstance(value, str) and value.startswith(self.token_prefix)

    def encrypt_text(self, value: str | None) -> str | None:
        # Encripta un string con Fernet y le pone el prefijo enc:v1:
        if value is None:
            return None
        if self.is_encrypted(value):
            return value
        token = self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")
        return f"{self.token_prefix}{token}"

    def decrypt_text(self, value: Any) -> str | None:
        # Descifra un valor que tenga el prefijo enc:v1:
        if value is None:
            return None
        if not isinstance(value, str):
            return str(value)
        if not self.is_encrypted(value):
            return value
        token = value[len(self.token_prefix):]
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("No se pudo descifrar un valor de la base de datos") from exc

    def json_to_storage(self, value: Any) -> str | None:
        if value is None:
            return None
        if self.is_encrypted(value):
            return value
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    def json_from_storage(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (dict, list, int, float, bool)):
            return value
        plain_text = self.decrypt_text(value)
        if plain_text is None:
            return None
        return json.loads(plain_text)

    def lookup_digest(self, value: str | None) -> str | None:
        # Genera un HMAC-SHA256 para poder buscar registros sin descifrar
        if value is None:
            return None
        digest = hmac.new(self._lookup_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{self.lookup_prefix}{digest}"


# Instancia global que usan los modelos y servicios
database_crypto = DatabaseCrypto(settings.database_encryption_key)


# TypeDecorator de SQLAlchemy: encripta/descifra automaticamente al leer/escribir
class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> str | None:
        if value is None:
            return None
        return database_crypto.encrypt_text(str(value))

    def process_result_value(self, value: Any, dialect) -> str | None:
        return database_crypto.decrypt_text(value)


# Lo mismo pero para campos JSON: serializa a texto y luego encripta
class EncryptedJSON(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect) -> str | None:
        plain_text = database_crypto.json_to_storage(value)
        if plain_text is None:
            return None
        return database_crypto.encrypt_text(plain_text)

    def process_result_value(self, value: Any, dialect) -> Any:
        return database_crypto.json_from_storage(value)
