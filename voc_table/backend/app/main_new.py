# FastAPI 엔트리 포인트 (리팩토링 버전)
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Optional

# 기존 모듈 import
from . import crud, schemas
from .db import get_db
from .dependencies import get_current_user, require_auth_level, get_client_ip
from .logging_conf import log_permission_denied

# 라우터 import
from .routers import auth, users, voc, companies, contacts, projects, ai, export

# FastAPI 앱 초기화
app = FastAPI(
    title="VOC Table API",
    description="AI VOC 시스템 API (Refactored with Cookie Auth)",
    version="2.0.1"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://172.16.5.75:8501",
        "http://172.16.5.*:8501",
        "http://172.16.5.75:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 헬스체크
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    return {"status": "OK", "timestamp": datetime.utcnow(), "version": "2.0.0-refactored"}

# 라우터 등록
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(voc.router, prefix="/voc", tags=["voc"])
app.include_router(companies.router, prefix="/companies", tags=["companies"])
app.include_router(contacts.router, prefix="/contacts", tags=["contacts"])
app.include_router(projects.router, prefix="/projects", tags=["projects"])
app.include_router(ai.router, prefix="/ai", tags=["ai"])
app.include_router(export.router, prefix="/export", tags=["export"])

# 루트 엔드포인트
@app.get("/")
async def root():
    """API 루트"""
    return {
        "message": "VOC Table API (Refactored)",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health"
    }

# =============================================================================
# Admin 엔드포인트들 (임시로 유지)
# =============================================================================

@app.post("/admin/setup-default-hr")
async def setup_default_hr(db: Session = Depends(get_db), request: Request = None):
    """기본 HR 관리자 계정 설정"""
    existing_hr_admins = crud.get_users_by_auth_level(db, auth_level=5)
    admin_emails = [user.email for user in existing_hr_admins if user.email.startswith("admin")]

    if admin_emails:
        return {
            "message": "HR admin accounts already exist",
            "existing_admins": admin_emails,
            "note": "Use existing admin accounts or contact system administrator"
        }

    hr_admin_data = schemas.UserCreate(
        email="admin@mobilint.com",
        username="admin",
        password="0000",
        auth_level=5,
        is_active=True
    )

    ip = get_client_ip(request) if request else None
    hr_admin = crud.create_user(db=db, user=hr_admin_data, ip=ip)

    return {
        "message": "Default HR admin account created successfully",
        "credentials": {"email": "admin@mobilint.com", "password": "0000"},
        "user": hr_admin
    }

@app.post("/admin/setup-dummy-users")
async def setup_dummy_users(
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4)),
    request: Request = None
):
    """더미 사용자 생성"""
    dummy_users_data = [
        {"email": "user1@test.com", "username": "user1", "password": "0000", "auth_level": 1},
        {"email": "user2@test.com", "username": "user2", "password": "0000", "auth_level": 2},
        {"email": "user3@test.com", "username": "user3", "password": "0000", "auth_level": 3},
    ]

    created_users = []
    ip = get_client_ip(request) if request else None

    for user_data in dummy_users_data:
        user_create = schemas.UserCreate(**user_data, is_active=True)
        user = crud.create_user(db=db, user=user_create, ip=ip)
        created_users.append(user)

    return {"message": f"{len(created_users)} dummy users created", "users": created_users}

@app.post("/admin/setup-sample-data")
async def setup_sample_data(
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),
    request: Request = None
):
    """샘플 데이터 생성"""
    try:
        ip = get_client_ip(request) if request else None

        # 샘플 회사 생성
        sample_companies = [
            {"name": "삼성전자", "domain": "samsung.com", "revenue": "1000억", "employee": 50000, "nation": "한국"},
            {"name": "LG전자", "domain": "lg.com", "revenue": "500억", "employee": 25000, "nation": "한국"},
        ]

        created_companies = []
        for company_data in sample_companies:
            company_create = schemas.CompanyCreate(**company_data)
            company = crud.create_company(db=db, company=company_create, user_id=current_user.id, ip=ip)
            created_companies.append(company)

        return {
            "message": "Sample data created successfully",
            "created_data": {"companies": len(created_companies)}
        }
    except Exception as e:
        return {"message": f"Error creating sample data: {str(e)}", "error": str(e)}

# Audit Log 엔드포인트
@app.get("/audit-logs/", response_model=list[schemas.AuditLog])
async def read_audit_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))
):
    """감사로그 조회 (레벨 4 이상)"""
    logs = crud.get_audit_logs(db, skip=skip, limit=limit)
    return logs
