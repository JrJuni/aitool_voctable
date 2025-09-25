# 로깅 설정 및 보안 이벤트 로깅
import logging
import os
from datetime import datetime
from typing import Optional

# 로그 디렉토리 생성
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 일 단위 로그 파일 핸들러 설정
def setup_logging():
    """로깅 설정 초기화"""
    # 로그 포맷: ts | level | req_id | user_id | method path status ms | msg
    log_format = "%(asctime)s | %(levelname)s | %(message)s"
    
    # 파일 핸들러 (일 단위)
    today = datetime.now().strftime("%Y%m%d")
    log_file = f"{log_dir}/log_{today}.txt"
    
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(log_format))
    
    # 콘솔 핸들러
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format))
    
    # 루트 로거 설정
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

# 보안 이벤트 로깅 함수들
def log_user_creation(user_id: int, email: str, auth_level: int, ip: Optional[str] = None):
    """사용자 생성 로그"""
    logging.info(f"USER_CREATE | user_id={user_id} | email={email} | auth_level={auth_level} | ip={ip}")

def log_user_update(user_id: int, email: str, updated_fields: dict, ip: Optional[str] = None):
    """사용자 정보 수정 로그"""
    fields_str = ", ".join([f"{k}={v}" for k, v in updated_fields.items()])
    logging.info(f"USER_UPDATE | user_id={user_id} | email={email} | fields=[{fields_str}] | ip={ip}")

def log_login_success(user_id: int, email: str, ip: Optional[str] = None, user_agent: Optional[str] = None):
    """로그인 성공 로그"""
    logging.info(f"LOGIN_SUCCESS | user_id={user_id} | email={email} | ip={ip} | ua={user_agent}")

def log_login_failure(email: str, reason: str, ip: Optional[str] = None, user_agent: Optional[str] = None):
    """로그인 실패 로그"""
    logging.warning(f"LOGIN_FAILURE | email={email} | reason={reason} | ip={ip} | ua={user_agent}")

def log_logout(user_id: int, email: str, ip: Optional[str] = None):
    """로그아웃 로그"""
    logging.info(f"LOGOUT | user_id={user_id} | email={email} | ip={ip}")

def log_auth_failure(user_id: Optional[int], email: Optional[str], action: str, reason: str, ip: Optional[str] = None):
    """인증 실패 로그"""
    logging.warning(f"AUTH_FAILURE | user_id={user_id} | email={email} | action={action} | reason={reason} | ip={ip}")

def log_permission_denied(user_id: int, email: str, action: str, required_level: int, current_level: int, ip: Optional[str] = None):
    """권한 부족 로그"""
    logging.warning(f"PERMISSION_DENIED | user_id={user_id} | email={email} | action={action} | required_level={required_level} | current_level={current_level} | ip={ip}")

# 로깅 초기화
logger = setup_logging()