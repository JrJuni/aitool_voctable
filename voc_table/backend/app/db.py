# Database configuration and dependency
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file in project root
# Navigate from backend/app/db.py to project root (../../..)
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

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