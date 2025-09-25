# FastAPI 엔트리 포인트
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import jwt
import os

from . import crud, schemas
from .db import get_db
from .logging_conf import (
    log_login_success, log_login_failure, log_logout, 
    log_auth_failure, log_permission_denied
)
from . import excel_io

# FastAPI 앱 초기화
app = FastAPI(
    title="VOC Table API",
    description="AI VOC 시스템 API",
    version="1.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",  # 로컬 Streamlit 프론트엔드
        "http://172.16.5.75:8501",  # 내부망 Streamlit 프론트엔드
        "http://172.16.5.*:8501",  # 내부망 대역 (필요시)
        "http://172.16.5.75:8000",  # 내부망 API 직접 접근
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MIN", "30"))

# OAuth2 스키마
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# JWT 토큰 생성
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """JWT 액세스 토큰 생성"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 현재 사용자 인증
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """현재 로그인한 사용자 정보 조회"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = crud.get_user_by_id(db, user_id=user_id)
    if user is None:
        raise credentials_exception
    
    return user

# 권한 검증 의존성
def require_auth_level(required_level: int):
    """권한 레벨 검증 데코레이터"""
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

# 클라이언트 IP 추출
def get_client_ip(request: Request) -> str:
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host

# 헬스체크
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    return {"status": "OK", "timestamp": datetime.utcnow()}

# =============================================================================
# 인증 관련 엔드포인트
# =============================================================================

@app.post("/auth/login", response_model=schemas.Token)
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

@app.get("/auth/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    """현재 로그인한 사용자 정보 조회"""
    return current_user

@app.post("/auth/logout")
async def logout(
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 로그아웃"""
    ip = get_client_ip(request) if request else None
    
    # 로그아웃 로그
    log_logout(current_user.id, current_user.email, ip)
    
    return {"message": "Successfully logged out"}

# =============================================================================
# 사용자 관리 엔드포인트
# =============================================================================

@app.get("/users/", response_model=list[schemas.User])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))  # 레벨 4 이상만 조회 가능
):
    """사용자 목록 조회 (관리자만)"""
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

@app.post("/users/register", response_model=schemas.User)
async def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    request: Request = None
):
    """사용자 회원가입 (누구나 가능, 레벨 0으로 승인 대기)"""
    # 이메일 중복 확인
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # 회원가입 시에는 항상 레벨 0으로 설정 (승인 대기)
    user.auth_level = 0
    
    ip = get_client_ip(request) if request else None
    return crud.create_user(db=db, user=user, ip=ip)

@app.post("/users/", response_model=schemas.User)
async def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """관리자 사용자 생성 (레벨 3 이상)"""
    # 레벨 3 이상만 사용자 생성 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"create_user", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to create users"
        )
    
    # 이메일 중복 확인
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # 레벨 5는 생성 불가 (대표님 고정)
    if user.auth_level == 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"create_user_level_5", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5 users cannot be created (CEO level is fixed)"
        )
    
    # 권한별 생성 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 생성 가능
        if user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"create_user_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only create users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 생성 가능
        if user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"create_user_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only create users with level 0-4"
            )
    
    ip = get_client_ip(request) if request else None
    return crud.create_user(db=db, user=user, ip=ip)

@app.get("/users/{user_id}", response_model=schemas.User)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """사용자 정보 조회"""
    db_user = crud.get_user_by_id(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인 정보이거나 권한에 따라 조회 가능
    if current_user.id != user_id:
        if current_user.auth_level < 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"read_user_{user_id}", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3+ required to view other users"
            )
        
        # 권한별 조회 가능 레벨 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3만 조회 가능
            if db_user.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"read_user_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only view users with level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 조회 가능 (레벨 5는 조회 불가)
            if db_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"read_user_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only view users with level 0-4"
                )
    
    return db_user

@app.patch("/users/{user_id}", response_model=schemas.User)
async def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 정보 수정"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    
    # 본인 정보이거나 권한에 따라 수정 가능
    if current_user.id != user_id:
        if current_user.auth_level < 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"update_user_{user_id}", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3+ required to modify other users"
            )
        
        # 권한별 수정 가능 레벨 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3만 수정 가능
            if target_user.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"update_user_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only modify users with level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 수정 가능 (레벨 5는 수정 불가)
            if target_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"update_user_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only modify users with level 0-4"
                )
    
    # 권한 레벨 변경 권한 검증
    if user_update.auth_level is not None:
        # 레벨 5는 변경 불가 (대표님 고정)
        if user_update.auth_level == 5:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"change_auth_level_{user_id}_to_5", 5, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 5 cannot be set (CEO level is fixed)"
            )
        
        # 권한별 레벨 변경 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3까지만 설정 가능
            if user_update.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"change_auth_level_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only set auth level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4까지만 설정 가능
            if user_update.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"change_auth_level_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only set auth level 0-4"
                )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 비활성화 (is_active = False)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인은 비활성화 불가
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot deactivate your own account"
        )
    
    # 레벨 3 이상만 사용자 비활성화 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"deactivate_user_{user_id}", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to deactivate users"
        )
    
    # 권한별 비활성화 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 비활성화 가능
        if target_user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"deactivate_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only deactivate users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 비활성화 가능 (레벨 5는 비활성화 불가)
        if target_user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"deactivate_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only deactivate users with level 0-4"
            )
    
    # 사용자 비활성화
    user_update = schemas.UserUpdate(is_active=False)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deactivated successfully"}

@app.patch("/users/{user_id}/activate")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 활성화 (is_active = True)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 레벨 3 이상만 사용자 활성화 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"activate_user_{user_id}", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to activate users"
        )
    
    # 권한별 활성화 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 활성화 가능
        if target_user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"activate_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only activate users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 활성화 가능 (레벨 5는 활성화 불가)
        if target_user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"activate_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only activate users with level 0-4"
            )
    
    # 사용자 활성화
    user_update = schemas.UserUpdate(is_active=True)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User activated successfully"}

@app.patch("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 비밀번호 초기화 (0000으로 설정)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인 비밀번호 초기화 또는 레벨 4 이상만 다른 사용자 비밀번호 초기화 가능
    if current_user.id != user_id:
        if current_user.auth_level < 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"reset_password_{user_id}", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4+ required to reset other users' passwords"
            )
        
        # 권한별 비밀번호 초기화 가능 레벨 제한
        if current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 비밀번호 초기화 가능 (레벨 5는 불가)
            if target_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"reset_password_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only reset passwords for users with level 0-4"
                )
    
    # 비밀번호 초기화 (0000으로 설정)
    user_update = schemas.UserUpdate(password="0000")
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 로그
    from .logging_conf import log_user_update
    log_user_update(
        current_user.id, current_user.email, 
        {"password_reset": f"User {target_user.email} password reset to 0000"}, ip
    )
    
    return {"message": "Password reset successfully to 0000"}

@app.patch("/users/me", response_model=schemas.User)
async def update_my_profile(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """본인 개인정보 수정 (모든 사용자 가능)"""
    # 본인 정보만 수정 가능
    # auth_level은 변경 불가 (보안상)
    if user_update.auth_level is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own auth level"
        )
    
    # is_active는 변경 불가 (보안상)
    if user_update.is_active is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own active status"
        )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=current_user.id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/reset-password-admin")
async def reset_user_password_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """HR 관리자용 비밀번호 초기화 (레벨 5 전용)"""
    # HR 관리자 계정만 사용 가능 (레벨 5 + 특별한 이메일 패턴)
    if current_user.auth_level != 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"admin_reset_password_{user_id}", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR admin accounts can use this endpoint"
        )
    
    # HR 관리자 계정 확인 (admin으로 시작하는 이메일)
    if not current_user.email.startswith("admin"):
        log_permission_denied(
            current_user.id, current_user.email, 
            f"admin_reset_password_{user_id}_not_admin", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin accounts can use this endpoint"
        )
    
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 (0000으로 설정)
    user_update = schemas.UserUpdate(password="0000")
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 로그
    from .logging_conf import log_user_update
    log_user_update(
        current_user.id, current_user.email, 
        {"admin_password_reset": f"HR Admin reset password for user {target_user.email} to 0000"}, ip
    )
    
    return {"message": f"Password reset successfully to 0000 for user {target_user.email}"}

@app.patch("/users/me/admin-profile")
async def update_admin_profile(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """HR 관리자용 본인 정보 수정 (비밀번호만 변경 가능)"""
    # HR 관리자 계정만 사용 가능 (레벨 5 + 특별한 이메일 패턴)
    if current_user.auth_level != 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR admin accounts can use this endpoint"
        )
    
    # HR 관리자 계정 확인 (admin으로 시작하는 이메일)
    if not current_user.email.startswith("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin accounts can use this endpoint"
        )
    
    # HR 관리자는 비밀번호만 변경 가능
    if user_update.email is not None or user_update.name is not None or user_update.auth_level is not None or user_update.is_active is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="HR admin can only change password"
        )
    
    # 비밀번호만 변경 가능
    if user_update.password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only password can be updated for HR admin"
        )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=current_user.id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.delete("/users/{user_id}/hard")
async def hard_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """사용자 완전 삭제 (레벨 5 이상만)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 레벨 5 이상만 완전 삭제 가능
    if current_user.auth_level < 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"hard_delete_user_{user_id}", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5+ required for permanent deletion"
        )
    
    # 본인은 삭제 불가
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot permanently delete your own account"
        )
    
    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User permanently deleted"}

@app.patch("/users/{user_id}/approve", response_model=schemas.User)
async def approve_user(
    user_id: int,
    new_auth_level: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),  # 레벨 3 이상만 승인 가능
    request: Request = None
):
    """사용자 승인 (레벨 0 → 지정된 레벨로 승인)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 승인 대기 상태(레벨 0)가 아니면 승인 불가
    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not in pending approval status"
        )
    
    # 레벨 5는 승인 불가 (대표님 고정)
    if new_auth_level == 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"approve_user_{user_id}_to_5", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5 cannot be approved (CEO level is fixed)"
        )
    
    # 권한별 승인 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 1-3까지만 승인 가능
        if new_auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"approve_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only approve users with level 1-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 1-4까지만 승인 가능
        if new_auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"approve_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only approve users with level 1-4"
            )
    
    # 사용자 승인 (레벨 변경)
    user_update = schemas.UserUpdate(auth_level=new_auth_level)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/reject")
async def reject_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),  # 레벨 3 이상만 거부 가능
    request: Request = None
):
    """사용자 가입 거부 (레벨 0 사용자 삭제)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 승인 대기 상태(레벨 0)가 아니면 거부 불가
    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not in pending approval status"
        )
    
    # 사용자 완전 삭제 (가입 거부)
    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User registration rejected and deleted"}

@app.post("/admin/setup-default-hr")
async def setup_default_hr_admin(
    db: Session = Depends(get_db),
    request: Request = None
):
    """기본 HR 관리자 계정 설정 (admin@mobilint.com / 0000)"""
    # 기존 HR 관리자 계정이 있는지 확인
    existing_hr_admins = crud.get_users_by_auth_level(db, auth_level=5)
    admin_emails = [user.email for user in existing_hr_admins if user.email.startswith("admin")]
    
    if admin_emails:
        return {
            "message": "HR admin accounts already exist",
            "existing_admins": admin_emails,
            "note": "Use existing admin accounts or contact system administrator"
        }
    
    # 기본 HR 관리자 계정 생성
    hr_admin_data = schemas.UserCreate(
        email="admin@mobilint.com",
        name="HR Admin",
        password="0000",
        auth_level=5,
        is_active=True
    )
    
    ip = get_client_ip(request) if request else None
    hr_admin = crud.create_user(db=db, user=hr_admin_data, ip=ip)
    
    return {
        "message": "Default HR admin account created successfully",
        "credentials": {
            "email": "admin@mobilint.com",
            "password": "0000",
            "note": "Please change password on first login"
        },
        "user": hr_admin
    }

@app.get("/users/pending", response_model=list[schemas.User])
async def get_pending_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3))  # 레벨 3 이상만 조회 가능
):
    """승인 대기 사용자 목록 조회 (레벨 0 사용자들)"""
    pending_users = crud.get_users_by_auth_level(db, auth_level=0, skip=skip, limit=limit)
    return pending_users

@app.post("/admin/setup-dummy-users")
async def setup_dummy_users(
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4)),  # 레벨 4 이상만 가능
    request: Request = None
):
    """한국 이름의 더미 사용자 데이터 설정"""
    ip = get_client_ip(request) if request else None
    
    # 한국 이름의 더미 사용자 데이터 (우리 회사 직원들)
    dummy_users = [
        {
            "email": "kim.chulsoo@mobilint.com",
            "name": "김철수",
            "password": "0000",
            "auth_level": 1,
            "is_active": True
        },
        {
            "email": "lee.younghee@mobilint.com", 
            "name": "이영희",
            "password": "0000",
            "auth_level": 2,
            "is_active": True
        },
        {
            "email": "park.minsu@mobilint.com",
            "name": "박민수", 
            "password": "0000",
            "auth_level": 3,
            "is_active": True
        },
        {
            "email": "choi.jiyoung@mobilint.com",
            "name": "최지영",
            "password": "0000",
            "auth_level": 2,
            "is_active": True
        },
        {
            "email": "jung.suhyun@mobilint.com",
            "name": "정수현",
            "password": "0000",
            "auth_level": 1,
            "is_active": True
        }
    ]
    
    # 기존 더미 사용자들이 있는지 확인
    existing_dummy_users = []
    for user_data in dummy_users:
        existing_user = crud.get_user_by_email(db, user_data["email"])
        if existing_user:
            existing_dummy_users.append(existing_user)
    
    if existing_dummy_users:
        return {
            "message": "일부 더미 사용자들이 이미 존재합니다",
            "existing_users": [{"id": user.id, "name": user.name, "email": user.email, "auth_level": user.auth_level} for user in existing_dummy_users],
            "created_users": []
        }
    
    created_users = []
    for user_data in dummy_users:
        user_create = schemas.UserCreate(**user_data)
        created_user = crud.create_user(db=db, user=user_create, ip=ip)
        created_users.append(created_user)
    
    return {
        "message": f"{len(created_users)}명의 더미 사용자가 생성되었습니다",
        "created_users": [{"id": user.id, "name": user.name, "email": user.email, "auth_level": user.auth_level} for user in created_users]
    }

# =============================================================================
# VOC 관련 엔드포인트
# =============================================================================

@app.get("/voc/", response_model=list[schemas.VOC])
async def read_vocs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """VOC 목록 조회"""
    vocs = crud.get_vocs(db, skip=skip, limit=limit)
    return vocs

@app.get("/voc/search")
async def search_vocs(
    skip: int = 0,
    limit: int = 100,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    company_id: Optional[int] = None,
    contact_id: Optional[int] = None,
    project_id: Optional[int] = None,
    assignee_user_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    search_text: Optional[str] = None,
    search_company: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    include_deleted: bool = False,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """VOC 검색/필터링"""
    from .filters import VOCFilterParams, get_filtered_vocs
    from datetime import datetime

    # 날짜 문자열을 date 객체로 변환
    parsed_from_date = None
    parsed_to_date = None

    if from_date:
        try:
            parsed_from_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format. Use YYYY-MM-DD")

    if to_date:
        try:
            parsed_to_date = datetime.strptime(to_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format. Use YYYY-MM-DD")

    # 필터 파라미터 생성
    filters = VOCFilterParams(
        skip=skip,
        limit=limit,
        from_date=parsed_from_date,
        to_date=parsed_to_date,
        company_id=company_id,
        contact_id=contact_id,
        project_id=project_id,
        assignee_user_id=assignee_user_id,
        status=status,
        priority=priority,
        search_text=search_text,
        search_company=search_company,
        sort_by=sort_by,
        sort_order=sort_order,
        include_deleted=include_deleted
    )

    return get_filtered_vocs(db, filters)

@app.get("/voc/statistics")
async def get_voc_stats(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    company_id: Optional[int] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """VOC 통계 조회"""
    from .filters import VOCFilterParams, get_voc_statistics
    from datetime import datetime

    # 날짜 파싱
    parsed_from_date = None
    parsed_to_date = None

    if from_date:
        try:
            parsed_from_date = datetime.strptime(from_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format")

    if to_date:
        try:
            parsed_to_date = datetime.strptime(to_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format")

    filters = VOCFilterParams(
        from_date=parsed_from_date,
        to_date=parsed_to_date,
        company_id=company_id,
        status=status,
        priority=priority
    )

    return get_voc_statistics(db, filters)

@app.post("/voc/", response_model=schemas.VOC)
async def create_voc(
    voc: schemas.VOCCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """VOC 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_voc(db=db, voc=voc, user_id=current_user.id, ip=ip)

@app.get("/voc/{voc_id}", response_model=schemas.VOC)
async def read_voc(
    voc_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """VOC 상세 조회"""
    voc = crud.get_voc(db, voc_id=voc_id)
    if voc is None:
        raise HTTPException(status_code=404, detail="VOC not found")
    return voc

@app.patch("/voc/{voc_id}", response_model=schemas.VOC)
async def update_voc(
    voc_id: int,
    voc_update: schemas.VOCUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """VOC 수정"""
    ip = get_client_ip(request) if request else None
    voc = crud.update_voc(db=db, voc_id=voc_id, voc_update=voc_update, user_id=current_user.id, ip=ip)
    if voc is None:
        raise HTTPException(status_code=404, detail="VOC not found")
    return voc

@app.delete("/voc/{voc_id}")
async def delete_voc(
    voc_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """VOC 삭제"""
    ip = get_client_ip(request) if request else None
    success = crud.delete_voc(db=db, voc_id=voc_id, user_id=current_user.id, ip=ip)
    if not success:
        raise HTTPException(status_code=404, detail="VOC not found")
    return {"message": "VOC deleted successfully"}

@app.patch("/voc/bulk-update", response_model=schemas.BulkUpdateResponse)
async def bulk_update_vocs(
    bulk_update: schemas.BulkVOCUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """대량 VOC 업데이트"""
    ip = get_client_ip(request) if request else None
    result = crud.bulk_update_vocs(
        db=db, 
        voc_updates=bulk_update.vocs, 
        user_id=current_user.id, 
        ip=ip
    )
    return schemas.BulkUpdateResponse(**result)

# =============================================================================
# Company 관련 엔드포인트
# =============================================================================

@app.get("/companies/", response_model=list[schemas.Company])
async def read_companies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))  # 레벨 2 이상만 조회 가능
):
    """회사 목록 조회"""
    companies = crud.get_companies(db, skip=skip, limit=limit)
    return companies

@app.get("/companies/search")
async def search_companies(
    skip: int = 0,
    limit: int = 100,
    search_name: Optional[str] = None,
    nation: Optional[str] = None,
    min_employee: Optional[int] = None,
    max_employee: Optional[int] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """회사 검색/필터링"""
    from .filters import CompanyFilterParams, get_filtered_companies

    filters = CompanyFilterParams(
        skip=skip,
        limit=limit,
        search_name=search_name,
        nation=nation,
        min_employee=min_employee,
        max_employee=max_employee,
        sort_by=sort_by,
        sort_order=sort_order
    )

    return get_filtered_companies(db, filters)

@app.post("/companies/", response_model=schemas.Company)
async def create_company(
    company: schemas.CompanyCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """회사 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_company(db=db, company=company, user_id=current_user.id, ip=ip)

@app.get("/companies/{company_id}", response_model=schemas.Company)
async def read_company(
    company_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """회사 상세 조회"""
    company = crud.get_company(db, company_id=company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

@app.patch("/companies/{company_id}", response_model=schemas.Company)
async def update_company(
    company_id: int,
    company_update: schemas.CompanyUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """회사 수정"""
    ip = get_client_ip(request) if request else None
    company = crud.update_company(db=db, company_id=company_id, company_update=company_update, user_id=current_user.id, ip=ip)
    if company is None:
        raise HTTPException(status_code=404, detail="Company not found")
    return company

@app.delete("/companies/{company_id}")
async def delete_company(
    company_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """회사 삭제"""
    ip = get_client_ip(request) if request else None
    success = crud.delete_company(db=db, company_id=company_id, user_id=current_user.id, ip=ip)
    if not success:
        raise HTTPException(status_code=404, detail="Company not found")
    return {"message": "Company deleted successfully"}

@app.patch("/companies/bulk-update", response_model=schemas.BulkUpdateResponse)
async def bulk_update_companies(
    bulk_update: schemas.BulkCompanyUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """대량 Company 업데이트"""
    ip = get_client_ip(request) if request else None
    result = crud.bulk_update_companies(
        db=db, 
        company_updates=bulk_update.companies, 
        user_id=current_user.id, 
        ip=ip
    )
    return schemas.BulkUpdateResponse(**result)

# =============================================================================
# Contact 관련 엔드포인트
# =============================================================================

@app.get("/contacts/", response_model=list[schemas.Contact])
async def read_contacts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))  # 레벨 2 이상만 조회 가능
):
    """연락처 목록 조회"""
    contacts = crud.get_contacts(db, skip=skip, limit=limit)
    return contacts

@app.post("/contacts/", response_model=schemas.Contact)
async def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """연락처 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_contact(db=db, contact=contact, user_id=current_user.id, ip=ip)

@app.get("/contacts/{contact_id}", response_model=schemas.Contact)
async def read_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """연락처 상세 조회"""
    contact = crud.get_contact(db, contact_id=contact_id)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

@app.patch("/contacts/{contact_id}", response_model=schemas.Contact)
async def update_contact(
    contact_id: int,
    contact_update: schemas.ContactUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """연락처 수정"""
    ip = get_client_ip(request) if request else None
    contact = crud.update_contact(db=db, contact_id=contact_id, contact_update=contact_update, user_id=current_user.id, ip=ip)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

@app.delete("/contacts/{contact_id}")
async def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """연락처 삭제"""
    ip = get_client_ip(request) if request else None
    success = crud.delete_contact(db=db, contact_id=contact_id, user_id=current_user.id, ip=ip)
    if not success:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"message": "Contact deleted successfully"}

@app.patch("/contacts/bulk-update", response_model=schemas.BulkUpdateResponse)
async def bulk_update_contacts(
    bulk_update: schemas.BulkContactUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """대량 Contact 업데이트"""
    ip = get_client_ip(request) if request else None
    result = crud.bulk_update_contacts(
        db=db, 
        contact_updates=bulk_update.contacts, 
        user_id=current_user.id, 
        ip=ip
    )
    return schemas.BulkUpdateResponse(**result)

# =============================================================================
# Project 관련 엔드포인트
# =============================================================================

@app.get("/projects/", response_model=list[schemas.Project])
async def read_projects(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))  # 레벨 2 이상만 조회 가능
):
    """프로젝트 목록 조회"""
    projects = crud.get_projects(db, skip=skip, limit=limit)
    return projects

@app.post("/projects/", response_model=schemas.Project)
async def create_project(
    project: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """프로젝트 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_project(db=db, project=project, user_id=current_user.id, ip=ip)

@app.get("/projects/{project_id}", response_model=schemas.Project)
async def read_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """프로젝트 상세 조회"""
    project = crud.get_project(db, project_id=project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.patch("/projects/{project_id}", response_model=schemas.Project)
async def update_project(
    project_id: int,
    project_update: schemas.ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """프로젝트 수정"""
    ip = get_client_ip(request) if request else None
    project = crud.update_project(db=db, project_id=project_id, project_update=project_update, user_id=current_user.id, ip=ip)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.delete("/projects/{project_id}")
async def delete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """프로젝트 삭제"""
    ip = get_client_ip(request) if request else None
    success = crud.delete_project(db=db, project_id=project_id, user_id=current_user.id, ip=ip)
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"message": "Project deleted successfully"}

@app.get("/projects/search")
async def search_projects(
    skip: int = 0,
    limit: int = 100,
    company_id: Optional[int] = None,
    search_name: Optional[str] = None,
    field: Optional[str] = None,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """프로젝트 검색/필터링"""
    from .filters import ProjectFilterParams, get_filtered_projects

    filters = ProjectFilterParams(
        skip=skip,
        limit=limit,
        company_id=company_id,
        search_name=search_name,
        field=field,
        sort_by=sort_by,
        sort_order=sort_order
    )

    return get_filtered_projects(db, filters)

@app.patch("/projects/bulk-update", response_model=schemas.BulkUpdateResponse)
async def bulk_update_projects(
    bulk_update: schemas.BulkProjectUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """대량 Project 업데이트"""
    ip = get_client_ip(request) if request else None
    result = crud.bulk_update_projects(
        db=db, 
        project_updates=bulk_update.projects, 
        user_id=current_user.id, 
        ip=ip
    )
    return schemas.BulkUpdateResponse(**result)

# =============================================================================
# 감사 로그 엔드포인트
# =============================================================================

@app.get("/audit-logs/", response_model=list[schemas.AuditLog])
async def read_audit_logs(
    skip: int = 0,
    limit: int = 100,
    table_name: Optional[str] = None,
    actor_user_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))  # 레벨 4 이상만 조회 가능
):
    """감사 로그 조회 (관리자만)"""
    audit_logs = crud.get_audit_logs(
        db, skip=skip, limit=limit, 
        table_name=table_name, actor_user_id=actor_user_id
    )
    return audit_logs

# ================================
# AI 기능 엔드포인트
# ================================

@app.post("/ai/analyze/voc")
async def analyze_voc_text(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트를 분석하여 VOC 형태로 구조화
    - 회의록, 메일, 녹취록 등을 VOC 데이터로 변환
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from .ai_utils import analyze_voc_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다. 관리자에게 문의하세요."
            )

        # 컨텍스트 정보 구성
        context = {
            "user_id": current_user.id,
            "username": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request.context:
            context.update(request.context)

        # AI 분석 실행
        result = analyze_voc_content(request.text, context)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다. llama-cpp-python이 설치되어 있는지 확인하세요."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")

@app.post("/ai/analyze/project")
async def analyze_project_text(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트를 분석하여 프로젝트 형태로 구조화
    - 프로젝트 제안서, 기술 문서 등을 프로젝트 데이터로 변환
    - 권한: Level 2 이상
    """
    require_auth_level(current_user, 2)

    try:
        from .ai_utils import analyze_project_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        context = {
            "user_id": current_user.id,
            "username": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request.context:
            context.update(request.context)

        result = analyze_project_content(request.text, context)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")

@app.post("/ai/analyze/mixed")
async def analyze_mixed_content(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트 유형을 자동 판별하고 적절한 분석 수행
    - VOC, 프로젝트, 연락처 정보를 자동으로 구분하여 분석
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from .ai_utils import analyze_mixed_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        result = analyze_mixed_content(request.text)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")

@app.post("/ai/extract/contact")
async def extract_contact_info(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트에서 연락처 정보 추출
    - 이메일 서명, 명함, 자기소개에서 연락처 정보 추출
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from .ai_utils import extract_contact_info, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        result = extract_contact_info(request.text)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="연락처 정보 추출 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "contact_info": result,
            "extracted_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"연락처 추출 오류: {str(e)}")

@app.post("/ai/voc/{voc_id}/regenerate-summary")
async def regenerate_voc_summary(
    voc_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    기존 VOC의 AI 요약을 다시 생성
    - 권한: Level 2 이상
    """
    require_auth_level(current_user, 2)

    # VOC 조회
    voc = crud.get_voc(db, voc_id=voc_id)
    if not voc:
        raise HTTPException(status_code=404, detail="VOC를 찾을 수 없습니다")

    try:
        from .ai_utils import generate_ai_summary, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        # VOC 데이터로 요약 생성
        voc_data = {
            "content": voc.content,
            "action_item": voc.action_item,
            "status": voc.status,
            "priority": voc.priority
        }

        new_summary = generate_ai_summary(voc_data)

        # 업데이트
        updated_voc = crud.update_voc(
            db, voc_id=voc_id,
            voc=schemas.VOCUpdate(ai_summary=new_summary)
        )

        return {
            "success": True,
            "voc_id": voc_id,
            "new_summary": new_summary,
            "updated_at": updated_voc.updated_at
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"요약 생성 오류: {str(e)}")

@app.get("/ai/status")
async def get_ai_status(
    current_user: schemas.User = Depends(get_current_user)
):
    """
    AI 서비스 상태 조회
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from .ai_utils import llm
        from .config import settings

        return {
            "ai_enabled": settings.AI_ENABLED,
            "model_path": settings.MODEL_PATH,
            "model_loaded": llm is not None,
            "max_tokens": settings.AI_MAX_TOKENS,
            "temperature": settings.AI_TEMPERATURE,
            "context_length": settings.AI_CONTEXT_LENGTH,
            "status": "active" if llm is not None else "inactive"
        }

    except ImportError:
        return {
            "ai_enabled": False,
            "error": "AI 유틸리티를 불러올 수 없습니다.",
            "status": "unavailable"
        }

# Excel Export 엔드포인트들
@app.get("/export/voc")
async def export_voc_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    VOC 테이블만 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_voc_to_excel(db)
        return {
            "success": True,
            "message": "VOC Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VOC export failed: {str(e)}")

@app.get("/export/full")
async def export_full_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    Users 제외한 모든 테이블을 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_full_tables_to_excel(db)
        return {
            "success": True,
            "message": "Full Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full export failed: {str(e)}")

@app.get("/export/all")
async def export_all_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    모든 테이블을 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_all_tables_to_excel(db)
        return {
            "success": True,
            "message": "All tables Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"All export failed: {str(e)}")

@app.get("/export/biz")
async def export_biz_template_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    VOC와 Projects 2개 시트가 있는 비즈니스 템플릿 엑셀 파일 생성
    나중에 input 템플릿으로 사용할 예정
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_biz_template_to_excel(db)
        return {
            "success": True,
            "message": "Business template Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Business template export failed: {str(e)}")

@app.get("/export/table/{table_name}")
async def export_table_excel(
    table_name: str,
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    특정 테이블만 엑셀로 내보내기
    - 권한: Level 1 이상
    - table_name: users, companies, contacts, projects, vocs, audit_logs
    """
    try:
        filepath = excel_io.export_table_to_excel(db, table_name)
        return {
            "success": True,
            "message": f"Table {table_name} Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Table export failed: {str(e)}")

@app.get("/export/info")
async def get_export_info(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    모든 테이블의 기본 정보 반환 (레코드 수 등)
    - 권한: Level 1 이상
    """
    try:
        info = excel_io.get_table_info(db)
        return {
            "success": True,
            "tables": info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get table info: {str(e)}")