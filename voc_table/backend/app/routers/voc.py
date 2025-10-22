# VOC 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level, get_client_ip
from ..filters import VOCFilterParams, get_filtered_vocs, get_voc_statistics

router = APIRouter()


@router.get("/", response_model=List[schemas.VOC])
async def read_vocs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """VOC 목록 조회"""
    vocs = crud.get_vocs(db, skip=skip, limit=limit)
    return vocs


@router.get("/search")
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


@router.get("/statistics")
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


@router.post("/", response_model=schemas.VOC)
async def create_voc(
    voc: schemas.VOCCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """VOC 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_voc(db=db, voc=voc, user_id=current_user.id, ip=ip)


@router.get("/{voc_id}", response_model=schemas.VOC)
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


@router.patch("/{voc_id}", response_model=schemas.VOC)
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
        # 권한 검증 실패 또는 VOC가 존재하지 않음
        if not crud.check_voc_edit_permission(db, voc_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to edit this VOC"
            )
        raise HTTPException(status_code=404, detail="VOC not found")
    return voc


@router.delete("/{voc_id}")
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


@router.patch("/bulk-update", response_model=schemas.BulkUpdateResponse)
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
