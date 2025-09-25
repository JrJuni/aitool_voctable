# 개선된 FastAPI 엔트리 포인트
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import auth, users, voc, companies, contacts, projects, admin
from .db import create_tables

# FastAPI 앱 초기화
app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 데이터베이스 테이블 생성
create_tables()

# 라우터 등록
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(voc.router)
app.include_router(companies.router)
app.include_router(contacts.router)
app.include_router(projects.router)
app.include_router(admin.router)

# 헬스체크
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    return {
        "status": "OK",
        "version": settings.APP_VERSION,
        "timestamp": "2024-01-01T00:00:00Z"  # 실제로는 datetime.utcnow()
    }

# 루트 엔드포인트
@app.get("/")
async def root():
    """루트 엔드포인트"""
    return {
        "message": "VOC Table API",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }
