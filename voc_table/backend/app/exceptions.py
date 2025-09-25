# 커스텀 예외 클래스
from fastapi import HTTPException, status
from typing import Any, Dict, Optional

class VOCException(HTTPException):
    """VOC 시스템 기본 예외"""
    def __init__(
        self,
        status_code: int,
        detail: str,
        headers: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)

class UserNotFoundError(VOCException):
    """사용자를 찾을 수 없음"""
    def __init__(self, user_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found"
        )

class InsufficientPermissionError(VOCException):
    """권한 부족"""
    def __init__(self, required_level: int, current_level: int):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions. Required: {required_level}, Current: {current_level}"
        )

class DuplicateUserError(VOCException):
    """중복 사용자"""
    def __init__(self, email: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with email {email} already exists"
        )

class VOCNotFoundError(VOCException):
    """VOC를 찾을 수 없음"""
    def __init__(self, voc_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VOC with id {voc_id} not found"
        )

class CompanyNotFoundError(VOCException):
    """회사를 찾을 수 없음"""
    def __init__(self, company_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Company with id {company_id} not found"
        )

class ContactNotFoundError(VOCException):
    """연락처를 찾을 수 없음"""
    def __init__(self, contact_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Contact with id {contact_id} not found"
        )

class ProjectNotFoundError(VOCException):
    """프로젝트를 찾을 수 없음"""
    def __init__(self, project_id: int):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project with id {project_id} not found"
        )
