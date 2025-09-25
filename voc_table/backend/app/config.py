# 환경 설정 관리
import os
from typing import Optional

class Settings:
    """애플리케이션 설정"""
    
    # JWT 설정
    JWT_SECRET: str = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("TOKEN_EXPIRE_MIN", "30"))
    
    # 데이터베이스 설정
    DATABASE_URL: str = os.getenv("DATABASE_URL", "mysql+pymysql://voc_user:voc_password@mysql:3306/voc_database")
    
    # CORS 설정
    CORS_ORIGINS: list = [
        "http://localhost:8501",  # Streamlit 프론트엔드
        "http://127.0.0.1:8501",
        "http://frontend:8501",   # Docker 내부 네트워크
        "https://localhost",      # Nginx HTTPS
    ]
    
    # 애플리케이션 설정
    APP_TITLE: str = "VOC Table API"
    APP_DESCRIPTION: str = "AI VOC 시스템 API"
    APP_VERSION: str = "1.0.0"
    
    # 로깅 설정
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # 보안 설정
    PASSWORD_MIN_LENGTH: int = 6
    MAX_LOGIN_ATTEMPTS: int = 5
    
    # 권한 레벨 정의
    AUTH_LEVELS = {
        "PENDING": 0,      # 승인 대기
        "USER": 1,         # 일반 사용자
        "OPERATOR": 2,     # 운영자
        "MANAGER": 3,      # 관리자
        "ADMIN": 4,        # 시스템 관리자
        "SUPER_ADMIN": 5   # 최고 관리자
    }

    # AI 모델 설정
    MODEL_PATH: Optional[str] = os.getenv("MODEL_PATH", "../../models/EXAONE-4.0-1.2B-Q8_0.gguf")
    AI_ENABLED: bool = os.getenv("AI_ENABLED", "false").lower() == "true"
    AI_MAX_TOKENS: int = int(os.getenv("AI_MAX_TOKENS", "1024"))
    AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.2"))
    AI_CONTEXT_LENGTH: int = int(os.getenv("AI_CONTEXT_LENGTH", "4096"))

# 전역 설정 인스턴스
settings = Settings()
