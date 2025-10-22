# Project 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level, get_client_ip
from ..filters import ProjectFilterParams, get_filtered_projects

router = APIRouter()


@router.get("/", response_model=List[schemas.Project])
async def read_projects(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """프로젝트 목록 조회"""
    projects = crud.get_projects(db, skip=skip, limit=limit)
    return projects


@router.post("/", response_model=schemas.Project)
async def create_project(
    project: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """프로젝트 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_project(db=db, project=project, user_id=current_user.id, ip=ip)


@router.get("/{project_id}", response_model=schemas.Project)
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


@router.patch("/{project_id}", response_model=schemas.Project)
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
        # 권한 검증 실패 또는 프로젝트가 존재하지 않음
        if not crud.check_project_edit_permission(db, project_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to edit this project"
            )
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}")
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


@router.get("/search")
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


@router.patch("/bulk-update", response_model=schemas.BulkUpdateResponse)
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
