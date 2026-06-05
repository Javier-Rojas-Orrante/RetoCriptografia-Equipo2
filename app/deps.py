# Dependencia de FastAPI para inyectar la sesion de BD en cada endpoint
from collections.abc import Generator

from sqlalchemy.orm import Session

from app.db import SessionLocal


def get_db() -> Generator[Session, None, None]:
    # Abre una sesion, la pasa al endpoint y la cierra al terminar
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
