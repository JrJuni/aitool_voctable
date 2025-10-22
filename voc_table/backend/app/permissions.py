# 통합 권한 검증 모듈
from enum import Enum
from typing import Optional
from sqlalchemy.orm import Session
from . import crud
from .logging_conf import log_permission_denied


class PermissionLevel(Enum):
    """권한 검증 타입"""
    OWNER_ONLY = "owner_only"              # 본인만 수정 가능 (레벨 2 이하)
    LEVEL_1_PLUS = "level_1_plus"          # 레벨 1 이상
    LEVEL_2_PLUS = "level_2_plus"          # 레벨 2 이상
    LEVEL_3_PLUS = "level_3_plus"          # 레벨 3 이상
    LEVEL_4_PLUS = "level_4_plus"          # 레벨 4 이상 (관리자)
    LEVEL_5_ONLY = "level_5_only"          # 레벨 5만 (최고관리자)
    SAME_OR_LOWER = "same_or_lower"        # 동급 이하 유저만 수정 가능
    HIGHER_THAN_TARGET = "higher_than_target"  # 대상보다 높은 레벨만 가능


def check_user_permission(
    db: Session,
    current_user_id: int,
    required_level: int
) -> bool:
    """
    사용자 권한 레벨 검증

    Args:
        db: 데이터베이스 세션
        current_user_id: 현재 사용자 ID
        required_level: 요구되는 권한 레벨

    Returns:
        권한이 충분하면 True, 아니면 False
    """
    current_user = crud.get_user_by_id(db, current_user_id)
    if not current_user:
        return False

    if not current_user.is_active:
        return False

    return current_user.auth_level >= required_level


def check_edit_permission(
    db: Session,
    current_user_id: int,
    target_owner_id: Optional[int] = None,
    permission_type: PermissionLevel = PermissionLevel.LEVEL_2_PLUS
) -> bool:
    """
    통합 권한 검증 함수

    Args:
        db: 데이터베이스 세션
        current_user_id: 현재 사용자 ID
        target_owner_id: 대상 데이터의 소유자 ID (선택적)
        permission_type: 권한 검증 타입

    Returns:
        권한이 충분하면 True, 아니면 False
    """
    current_user = crud.get_user_by_id(db, current_user_id)
    if not current_user:
        return False

    if not current_user.is_active:
        return False

    # 권한 검증 로직
    if permission_type == PermissionLevel.LEVEL_1_PLUS:
        return current_user.auth_level >= 1

    if permission_type == PermissionLevel.LEVEL_2_PLUS:
        return current_user.auth_level >= 2

    if permission_type == PermissionLevel.LEVEL_3_PLUS:
        return current_user.auth_level >= 3

    if permission_type == PermissionLevel.LEVEL_4_PLUS:
        return current_user.auth_level >= 4

    if permission_type == PermissionLevel.LEVEL_5_ONLY:
        return current_user.auth_level >= 5

    if permission_type == PermissionLevel.OWNER_ONLY:
        # 레벨 2 이하는 본인 데이터만
        if current_user.auth_level <= 2:
            return current_user_id == target_owner_id
        # 레벨 3 이상은 제한 없음
        return True

    if permission_type == PermissionLevel.SAME_OR_LOWER:
        if target_owner_id is None:
            return False

        target_user = crud.get_user_by_id(db, target_owner_id)
        if not target_user:
            return False

        # 현재 사용자가 대상 사용자보다 같거나 높은 레벨이어야 함
        return current_user.auth_level >= target_user.auth_level

    if permission_type == PermissionLevel.HIGHER_THAN_TARGET:
        if target_owner_id is None:
            return False

        target_user = crud.get_user_by_id(db, target_owner_id)
        if not target_user:
            return False

        # 현재 사용자가 대상 사용자보다 높은 레벨이어야 함
        return current_user.auth_level > target_user.auth_level

    return False


def check_voc_edit_permission(db: Session, voc_id: int, current_user_id: int) -> bool:
    """
    VOC 수정 권한 검증 (기존 호환성 유지)

    - 레벨 2 이하: 본인이 작성한 VOC만 수정 가능
    - 레벨 3 이상: 자신의 레벨 이하 유저가 작성한 VOC 수정 가능
    """
    # VOC 조회
    db_voc = crud.get_voc(db, voc_id)
    if not db_voc:
        return False

    # 현재 사용자 정보 조회
    current_user = crud.get_user_by_id(db, current_user_id)
    if not current_user:
        return False

    # VOC 작성자 정보 조회
    voc_author = crud.get_user_by_id(db, db_voc.assignee_user_id)
    if not voc_author:
        return False

    # 권한 검증 로직
    if current_user.auth_level <= 2:
        # 레벨 2 이하: 본인 데이터만 수정 가능
        has_permission = current_user_id == db_voc.assignee_user_id
    else:
        # 레벨 3 이상: 자기 레벨 이하 유저가 작성한 데이터 수정 가능
        has_permission = current_user.auth_level >= voc_author.auth_level

    if not has_permission:
        log_permission_denied(
            current_user_id,
            current_user.email,
            f"edit_voc_{voc_id}",
            required_level=voc_author.auth_level,
            actual_level=current_user.auth_level
        )

    return has_permission


def check_company_edit_permission(db: Session, company_id: int, current_user_id: int) -> bool:
    """
    회사 수정 권한 검증 (기존 호환성 유지)

    - 레벨 2 이상만 수정 가능
    """
    return check_edit_permission(
        db=db,
        current_user_id=current_user_id,
        permission_type=PermissionLevel.LEVEL_2_PLUS
    )


def check_contact_edit_permission(db: Session, contact_id: int, current_user_id: int) -> bool:
    """
    연락처 수정 권한 검증 (기존 호환성 유지)

    - 레벨 2 이상만 수정 가능
    """
    return check_edit_permission(
        db=db,
        current_user_id=current_user_id,
        permission_type=PermissionLevel.LEVEL_2_PLUS
    )


def check_project_edit_permission(db: Session, project_id: int, current_user_id: int) -> bool:
    """
    프로젝트 수정 권한 검증 (기존 호환성 유지)

    - 레벨 2 이상만 수정 가능
    """
    return check_edit_permission(
        db=db,
        current_user_id=current_user_id,
        permission_type=PermissionLevel.LEVEL_2_PLUS
    )
