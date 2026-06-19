# 환경 설정 관리
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# 프로젝트 루트(voc_table/.env)의 환경변수를 읽는다(있을 경우). 파일을 생성/수정하지 않는다.
load_dotenv(dotenv_path=Path(__file__).parent.parent.parent / ".env")


def _require_env(name: str) -> str:
    """필수 시크릿/설정을 환경변수에서 읽고, 없으면 명시적으로 실패시킨다(fail-fast)."""
    val = os.getenv(name)
    if not val:
        raise RuntimeError(
            f"환경변수 {name}가 설정되지 않았습니다. "
            f"voc_table/env.example을 참고해 .env(또는 컨테이너 환경)에 값을 설정하세요."
        )
    return val


class Settings:
    """애플리케이션 설정 (시크릿은 환경변수에서만 읽는다 — 코드에 기본값을 박지 않는다)"""

    # JWT 설정 (필수)
    JWT_SECRET: str = _require_env("JWT_SECRET")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("TOKEN_EXPIRE_MIN", "30"))

    # 데이터베이스 설정 (필수 — 자격증명을 코드에 두지 않는다)
    DATABASE_URL: str = _require_env("DATABASE_URL")

    # 기본 관리자/비밀번호 정책 (환경변수로만 주입, 코드에 실값을 두지 않는다)
    DEFAULT_ADMIN_EMAIL: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
    # 비밀번호 초기화 기본값. 미설정 시 빈 값 → 초기화 기능은 경고 후 비활성(crud 참조).
    DEFAULT_RESET_PW: str = os.getenv("DEFAULT_RESET_PW", "")

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
