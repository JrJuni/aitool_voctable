# Contact 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level, get_client_ip

router = APIRouter()


@router.get("/", response_model=List[schemas.Contact])
async def read_contacts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2))
):
    """연락처 목록 조회"""
    contacts = crud.get_contacts(db, skip=skip, limit=limit)
    return contacts


@router.post("/", response_model=schemas.Contact)
async def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(2)),
    request: Request = None
):
    """연락처 생성"""
    ip = get_client_ip(request) if request else None
    return crud.create_contact(db=db, contact=contact, user_id=current_user.id, ip=ip)


@router.get("/{contact_id}", response_model=schemas.Contact)
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


@router.patch("/{contact_id}", response_model=schemas.Contact)
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
        # 권한 검증 실패 또는 연락처가 존재하지 않음
        if not crud.check_contact_edit_permission(db, contact_id, current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to edit this contact"
            )
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@router.delete("/{contact_id}")
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


@router.patch("/bulk-update", response_model=schemas.BulkUpdateResponse)
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
