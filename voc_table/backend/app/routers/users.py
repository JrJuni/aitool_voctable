# Users Router - 사용자 관리 API
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level, get_client_ip
from ..logging_conf import log_permission_denied, log_user_update
from ..permissions import check_user_permission, PermissionLevel

router = APIRouter()


@router.get("/", response_model=List[schemas.User])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))
):
    """사용자 목록 조회 (레벨 4 이상 관리자만)"""
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@router.post("/register", response_model=schemas.User)
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


@router.get("/pending", response_model=List[schemas.User])
async def get_pending_users(
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3))
):
    """승인 대기 중인 사용자 목록 조회 (레벨 3 이상)"""
    pending_users = crud.get_users_by_auth_level(db, auth_level=0)
    return pending_users


@router.patch("/{user_id}/approve", response_model=schemas.User)
async def approve_user(
    user_id: int,
    new_auth_level: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),
    request: Request = None
):
    """사용자 승인 (레벨 0 → 지정된 레벨로 승인)"""
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=400,
            detail="User is not in pending approval status"
        )

    # 레벨 5는 승인 불가
    if new_auth_level == 5:
        raise HTTPException(
            status_code=403,
            detail="Level 5 cannot be approved (CEO level is fixed)"
        )

    # 권한별 승인 가능 레벨 제한
    if current_user.auth_level == 3 and new_auth_level > 3:
        raise HTTPException(
            status_code=403,
            detail="Level 3 users can only approve users with level 1-3"
        )
    elif current_user.auth_level == 4 and new_auth_level > 4:
        raise HTTPException(
            status_code=403,
            detail="Level 4 users can only approve users with level 1-4"
        )

    user_update = schemas.UserUpdate(auth_level=new_auth_level)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return db_user


@router.patch("/{user_id}/reject")
async def reject_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),
    request: Request = None
):
    """사용자 가입 거부 (레벨 0 사용자 삭제)"""
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=400,
            detail="User is not in pending approval status"
        )

    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User registration rejected and deleted"}


@router.get("/{user_id}", response_model=schemas.User)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """사용자 정보 조회"""
    db_user = crud.get_user_by_id(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # 본인 정보이거나 레벨 3 이상만 조회 가능
    if current_user.id != user_id and current_user.auth_level < 3:
        raise HTTPException(
            status_code=403,
            detail="Level 3+ required to view other users"
        )

    return db_user


@router.patch("/{user_id}", response_model=schemas.User)
async def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 정보 수정"""
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")

    # 본인 정보가 아니면 레벨 3 이상만 수정 가능
    if current_user.id != user_id and current_user.auth_level < 3:
        raise HTTPException(
            status_code=403,
            detail="Level 3+ required to modify other users"
        )

    # 권한 레벨 변경은 레벨 3 이상만 가능
    if user_update.auth_level is not None:
        if user_update.auth_level == 5:
            raise HTTPException(
                status_code=403,
                detail="Level 5 cannot be set (CEO level is fixed)"
            )

        if current_user.auth_level == 3 and user_update.auth_level > 3:
            raise HTTPException(
                status_code=403,
                detail="Level 3 users can only set auth level 0-3"
            )
        elif current_user.auth_level == 4 and user_update.auth_level > 4:
            raise HTTPException(
                status_code=403,
                detail="Level 4 users can only set auth level 0-4"
            )

    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return db_user


@router.patch("/me", response_model=schemas.User)
async def update_my_profile(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """본인 개인정보 수정 (모든 사용자 가능)"""
    # auth_level, is_active는 변경 불가
    if user_update.auth_level is not None:
        raise HTTPException(
            status_code=403,
            detail="Cannot change your own auth level"
        )

    if user_update.is_active is not None:
        raise HTTPException(
            status_code=403,
            detail="Cannot change your own active status"
        )

    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=current_user.id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return db_user


@router.patch("/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),
    request: Request = None
):
    """사용자 비활성화 (is_active = False)"""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot deactivate your own account"
        )

    user_update = schemas.UserUpdate(is_active=False)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User deactivated successfully"}


@router.patch("/{user_id}/activate")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),
    request: Request = None
):
    """사용자 활성화 (is_active = True)"""
    user_update = schemas.UserUpdate(is_active=True)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User activated successfully"}


@router.patch("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 비밀번호 초기화 (0000으로 설정)"""
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # 본인 또는 레벨 4 이상만 가능
    if current_user.id != user_id and current_user.auth_level < 4:
        raise HTTPException(
            status_code=403,
            detail="Level 4+ required to reset other users' passwords"
        )

    user_update = schemas.UserUpdate(password="0000")
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    log_user_update(
        current_user.id, current_user.email,
        {"password_reset": f"User {target_user.email} password reset to 0000"}, ip
    )

    return {"message": "Password reset successfully to 0000"}


@router.delete("/{user_id}/hard")
async def hard_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(5))
):
    """사용자 완전 삭제 (레벨 5 이상만)"""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot permanently delete your own account"
        )

    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User permanently deleted"}
