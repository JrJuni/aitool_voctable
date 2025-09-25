# 인증 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import Optional

from .. import crud, schemas
from ..db import get_db
from ..logging_conf import log_login_success, log_login_failure, log_logout
from ..main import create_access_token, get_client_ip, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/login", response_model=schemas.Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    """사용자 로그인"""
    # 클라이언트 정보 추출
    ip = get_client_ip(request) if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    # 사용자 인증
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        log_login_failure(form_data.username, "Invalid credentials", ip, user_agent)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # JWT 토큰 생성
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    
    # 로그인 성공 로그
    log_login_success(user.id, user.email, ip, user_agent)
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    """현재 로그인한 사용자 정보 조회"""
    return current_user

@router.post("/logout")
async def logout(
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 로그아웃"""
    ip = get_client_ip(request) if request else None
    
    # 로그아웃 로그
    log_logout(current_user.id, current_user.email, ip)
    
    return {"message": "Successfully logged out"}
