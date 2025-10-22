# Company 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level, get_client_ip
from ..filters import CompanyFilterParams, get_filtered_companies

router = APIRouter()


@router.get("/", response_model=List[schemas.Company])
async def read_companies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """회사 목록 조회"""
    companies = crud.get_companies(db, skip=skip, limit=limit)
    return companies


@router.get("/search")
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


@router.post("/", response_model=schemas.Company)
async def create_company(
    company: schemas.CompanyCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """회사 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_company(db=db, company=company, user_id=current_user.id, ip=ip)


@router.get("/{company_id}", response_model=schemas.Company)
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


@router.patch("/{company_id}", response_model=schemas.Company)
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
        # 권한 검증 실패 또는 회사가 존재하지 않음
        if not crud.check_company_edit_permission(db, company_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to edit this company"
            )
        raise HTTPException(status_code=404, detail="Company not found")
    return company


@router.delete("/{company_id}")
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


@router.patch("/bulk-update", response_model=schemas.BulkUpdateResponse)
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
