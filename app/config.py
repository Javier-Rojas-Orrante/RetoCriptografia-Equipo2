from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "gestor-identidades-demo"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    database_url: str = "sqlite:///./identity_demo.db"
    certs_dir: str = "./generated/certs"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)


settings = Settings()
