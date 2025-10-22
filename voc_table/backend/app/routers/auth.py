# 인증 관련 라우터 (cookie auth added)
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import Optional

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, get_client_ip
from ..logging_conf import log_login_success, log_login_failure, log_logout
from ..auth_utils import create_access_token, decode_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()


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


@router.post("/login-cookie", response_model=schemas.Token)
async def login_with_cookie(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None,
    response: Response = None
):
    """쿠키 기반 사용자 로그인"""
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

    # 쿠키에 토큰 저장 (7일간 유지)
    if response:
        response.set_cookie(
            key="auth_token",
            value=access_token,
            max_age=7 * 24 * 60 * 60,  # 7일
            httponly=True,
            secure=False,  # HTTPS 환경에서는 True로 설정
            samesite="lax"
        )

    # 로그인 성공 로그
    log_login_success(user.id, user.email, ip, user_agent)

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout-cookie")
async def logout_with_cookie(
    response: Response,
    request: Request = None
):
    """쿠키 기반 사용자 로그아웃"""
    # 쿠키 삭제
    response.delete_cookie(key="auth_token")

    return {"message": "Successfully logged out"}


@router.get("/verify-cookie", response_model=schemas.User)
async def verify_cookie_auth(
    request: Request,
    db: Session = Depends(get_db)
):
    """쿠키 기반 인증 검증"""
    # 쿠키에서 토큰 추출
    auth_token = request.cookies.get("auth_token")

    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication cookie found"
        )

    # JWT 토큰 검증
    payload = decode_access_token(auth_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication cookie"
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    # 사용자 정보 조회
    user = crud.get_user_by_id(db, user_id=int(user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return user
