from pathlib import Path

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SESSION_SECRET = "cambia-esto-en-produccion-usa-variable-de-entorno"
DEFAULT_DATABASE_URL = f"sqlite:///{(BASE_DIR / 'identity_demo.db').resolve().as_posix()}"
DEFAULT_CERTS_DIR = BASE_DIR / "generated" / "certs"


class Settings(BaseSettings):
    app_name: str = "gestor-identidades-demo"
    app_host: str = Field(default="127.0.0.1", validation_alias=AliasChoices("APP_HOST", "HOST"))
    app_port: int = Field(default=8000, validation_alias=AliasChoices("APP_PORT", "PORT"))
    environment: str = "development"
    database_url: str = DEFAULT_DATABASE_URL
    database_encryption_key: str = ""
    certs_dir: Path = DEFAULT_CERTS_DIR
    session_secret: str = DEFAULT_SESSION_SECRET
    session_cookie_secure: bool | None = None
    seed_demo_data: bool = True
    allow_demo_admin_bypass: bool | None = None
    bootstrap_admin_full_name: str = "Administrador General"
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None

    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", case_sensitive=False)

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: str | None) -> str:
        if value is None:
            return DEFAULT_DATABASE_URL

        url = str(value).strip()
        if not url:
            return DEFAULT_DATABASE_URL
        if url.startswith("postgres://"):
            return "postgresql+psycopg://" + url.removeprefix("postgres://")
        if url.startswith("postgresql://"):
            return "postgresql+psycopg://" + url.removeprefix("postgresql://")
        if url.startswith("sqlite:///") and not url.startswith("sqlite:////") and url != "sqlite:///:memory:":
            sqlite_path = Path(url.removeprefix("sqlite:///"))
            resolved = sqlite_path if sqlite_path.is_absolute() else (BASE_DIR / sqlite_path).resolve()
            return f"sqlite:///{resolved.as_posix()}"
        return url

    @field_validator("certs_dir", mode="before")
    @classmethod
    def resolve_certs_dir(cls, value: str | Path | None) -> Path:
        if value in (None, ""):
            return DEFAULT_CERTS_DIR

        path = value if isinstance(value, Path) else Path(str(value))
        return path if path.is_absolute() else (BASE_DIR / path).resolve()

    @field_validator("bootstrap_admin_email")
    @classmethod
    def normalize_bootstrap_admin_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        return cleaned or None

    @field_validator("bootstrap_admin_full_name")
    @classmethod
    def normalize_bootstrap_admin_name(cls, value: str) -> str:
        cleaned = value.strip()
        return cleaned or "Administrador General"

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.is_production and self.session_secret == DEFAULT_SESSION_SECRET:
            raise ValueError("SESSION_SECRET debe definirse con un valor seguro en producción")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"

    @property
    def session_cookie_secure_resolved(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.is_production

    @property
    def demo_admin_bypass_enabled(self) -> bool:
        if self.allow_demo_admin_bypass is not None:
            return self.allow_demo_admin_bypass
        return self.seed_demo_data


settings = Settings()
