# Database configuration and dependency
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import os

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://voc_user:voc_password@mysql:3306/voc_database")

# Create database engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Session:
    """Database dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()