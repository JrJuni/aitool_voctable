# Database configuration and dependency
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Stub for testing - normally would connect to real database
engine = None
SessionLocal = None

def get_db() -> Session:
    """Database dependency for testing purposes"""
    if SessionLocal is None:
        raise RuntimeError("Database not configured")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()