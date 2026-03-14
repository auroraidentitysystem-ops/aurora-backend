# app/db/session.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """
    Dependency para FastAPI.
    Abre una sesión por request y la cierra al final.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()