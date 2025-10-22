# 의존성 주입 관리
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Optional
import jwt

from . import crud, schemas
from .db import get_db
from .config import settings
from .logging_conf import log_auth_failure, log_permission_denied
from .auth_utils import decode_access_token

# OAuth2 스키마
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> schemas.User:
    """현재 로그인한 사용자 정보 조회"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if not payload:
        raise credentials_exception

    user_id: int = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    user = crud.get_user_by_id(db, user_id=int(user_id))
    if user is None:
        raise credentials_exception

    return user

def require_auth_level(required_level: int):
    """권한 레벨 검증 의존성"""
    def auth_dependency(current_user: schemas.User = Depends(get_current_user)):
        if current_user.auth_level < required_level:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"auth_level_{required_level}", required_level, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required level: {required_level}, Current level: {current_user.auth_level}"
            )
        return current_user
    return auth_dependency

def require_active_user(current_user: schemas.User = Depends(get_current_user)) -> schemas.User:
    """활성 사용자만 허용"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

# 권한 레벨별 의존성
require_user = require_auth_level(settings.AUTH_LEVELS["USER"])
require_operator = require_auth_level(settings.AUTH_LEVELS["OPERATOR"])
require_manager = require_auth_level(settings.AUTH_LEVELS["MANAGER"])
require_admin = require_auth_level(settings.AUTH_LEVELS["ADMIN"])
require_super_admin = require_auth_level(settings.AUTH_LEVELS["SUPER_ADMIN"])


def get_client_ip(request: Request) -> str:
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
