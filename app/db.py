# Conexion a la base de datos con SQLAlchemy
# Soporta SQLite (dev) y PostgreSQL (produccion)
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings


# Clase base para todos los modelos ORM
class Base(DeclarativeBase):
    pass


# Configuracion del engine segun el tipo de BD
engine_kwargs = {"future": True, "pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)
# Factory de sesiones para usar en cada request
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
