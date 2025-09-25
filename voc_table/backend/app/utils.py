# 유틸리티 함수들
from fastapi import Request
from typing import Optional
import re

def get_client_ip(request: Request) -> str:
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host

def validate_email(email: str) -> bool:
    """이메일 형식 검증"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str) -> tuple[bool, str]:
    """비밀번호 강도 검증"""
    if len(password) < 6:
        return False, "비밀번호는 최소 6자 이상이어야 합니다"
    
    if not re.search(r'[A-Za-z]', password):
        return False, "비밀번호는 최소 하나의 영문자를 포함해야 합니다"
    
    if not re.search(r'\d', password):
        return False, "비밀번호는 최소 하나의 숫자를 포함해야 합니다"
    
    return True, ""

def sanitize_input(text: str) -> str:
    """입력 데이터 정제"""
    if not text:
        return ""
    
    # HTML 태그 제거
    text = re.sub(r'<[^>]+>', '', text)
    
    # 특수 문자 제거 (기본적인 XSS 방지)
    text = re.sub(r'[<>"\']', '', text)
    
    return text.strip()

def format_phone_number(phone: str) -> str:
    """전화번호 형식 정규화"""
    if not phone:
        return ""
    
    # 숫자만 추출
    digits = re.sub(r'\D', '', phone)
    
    # 한국 전화번호 형식
    if len(digits) == 11 and digits.startswith('010'):
        return f"{digits[:3]}-{digits[3:7]}-{digits[7:]}"
    elif len(digits) == 10:
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    
    return phone  # 형식을 알 수 없으면 원본 반환

def generate_username_from_email(email: str) -> str:
    """이메일에서 사용자명 생성"""
    if not email:
        return ""
    
    username = email.split('@')[0]
    # 특수 문자 제거
    username = re.sub(r'[^a-zA-Z0-9._-]', '', username)
    return username

def truncate_text(text: str, max_length: int = 100) -> str:
    """텍스트 길이 제한"""
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length-3] + "..."

def is_valid_auth_level(level: int) -> bool:
    """유효한 권한 레벨인지 확인"""
    return 0 <= level <= 5
