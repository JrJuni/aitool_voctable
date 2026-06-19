import streamlit as st
import streamlit.components.v1 as components
import requests
import hashlib
import time
import json
import os
import tempfile
import warnings
import secrets
from typing import Optional, Dict, Any
import streamlit_cookies_manager as cookies_manager
import mysql.connector
from mysql.connector import Error
import pandas as pd

# Streamlit cache deprecation 경고 억제
warnings.filterwarnings("ignore", message=".*st.cache.*", category=FutureWarning)

# 백엔드 API URL 설정
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

# 데이터 소스 우선순위 설정 (환경변수로 제어 가능)
DATA_SOURCE_PRIORITY = os.getenv("DATA_SOURCE_PRIORITY", "api_first")  # "api_first" 또는 "local_first"

# 기본 관리자/비밀번호 정책 (환경변수로만 주입 — 코드에 실값을 두지 않는다)
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
DEFAULT_RESET_PW = os.getenv("DEFAULT_RESET_PW", "")

# 사용자 데이터 파일 경로를 모듈 디렉터리 기준으로 고정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =============================================================================
# 쿠키 암호화 키 고정 시스템 (새로고침 문제 해결)
# =============================================================================
def get_or_create_cookie_key():
    """쿠키 암호화 키를 파일에서 읽거나 새로 생성"""
    cookie_key_file = os.path.join(BASE_DIR, ".cookie_secret_key")

    # 환경변수 우선 확인
    env_key = os.getenv("COOKIE_SECRET_KEY")
    if env_key and len(env_key) >= 32:
        return env_key

    # 파일에서 키 읽기
    if os.path.exists(cookie_key_file):
        try:
            with open(cookie_key_file, 'r', encoding='utf-8') as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except Exception:
            pass

    # 새 키 생성 및 저장
    new_key = secrets.token_urlsafe(32)
    try:
        with open(cookie_key_file, 'w', encoding='utf-8') as f:
            f.write(new_key)
        # 파일 권한 제한 (Unix 계열만)
        try:
            os.chmod(cookie_key_file, 0o600)
        except Exception:
            pass
    except Exception:
        pass

    return new_key

# 쿠키 매니저 초기화 (세션 쿠키 지원을 위해 CookieManager를 직접 확장)
class SessionCookieManager(cookies_manager.EncryptedCookieManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def set_session_cookie(self, key: str, value: str):
        """브라우저 세션 동안만 유지되는 쿠키 설정"""
        # 내부 CookieManager의 queue에 직접 접근하여 expires_at을 None으로 설정
        encrypted_value = self._encrypt(value.encode('utf-8')).decode('utf-8')
        self._cookie_manager._queue[key] = dict(
            value=encrypted_value,
            expires_at=None,  # 세션 쿠키로 설정
            path=self._cookie_manager._path,
        )

    def set_persistent_cookie(self, key: str, value: str, expires_days: int = 7):
        """영구 쿠키 설정 (지정된 일수 동안 유지)"""
        encrypted_value = self._encrypt(value.encode('utf-8')).decode('utf-8')
        expires_at = time.time() + (expires_days * 24 * 60 * 60)
        self._cookie_manager._queue[key] = dict(
            value=encrypted_value,
            expires_at=expires_at,  # 영구 쿠키로 설정
            path=self._cookie_manager._path,
        )

# 고정된 암호화 키로 쿠키 매니저 초기화
cookies = SessionCookieManager(
    prefix="voc_auth_",
    password=get_or_create_cookie_key()
)

# =============================================================================
# 로컬 DB 접근 함수들 (API 서버 의존성 제거)
# =============================================================================

def get_db_connection():
    """로컬 MySQL DB 연결"""
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3306")),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "voc_table"),
            charset='utf8mb4',
            autocommit=True
        )
        return connection
    except Error as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: DB 연결 실패: {e}")
        return None

def get_user_info_from_db(email: str) -> Optional[Dict[str, Any]]:
    """API 서버 없이 로컬 DB에서 사용자 정보 조회"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, email, username, auth_level, department, is_active
            FROM users 
            WHERE email = %s AND is_active = 1
        """, (email,))
        
        user = cursor.fetchone()
        if user:
            return {
                'id': user['id'],
                'email': user['email'],
                'username': user['username'],
                'auth_level': user['auth_level'],
                'department': user['department'] or '전략팀'
            }
        return None
    except Error as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: DB 조회 실패: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

def authenticate_user_locally(email: str, password: str) -> Optional[Dict[str, Any]]:
    """로컬 DB에서 사용자 인증 (비밀번호 해시 검증)"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, email, username, password_hash, auth_level, department, is_active
            FROM users 
            WHERE email = %s AND is_active = 1
        """, (email,))
        
        user = cursor.fetchone()
        if user:
            # 비밀번호 해시 검증 (passlib bcrypt 방식)
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            
            if pwd_context.verify(password, user['password_hash']):
                return {
                    'id': user['id'],
                    'email': user['email'],
                    'username': user['username'],
                    'auth_level': user['auth_level'],
                    'department': user['department'] or '전략팀',
                    'authenticated': True
                }
        return None
    except Error as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 로컬 인증 실패: {e}")
        return None
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()

# =============================================================================
# 백업 토큰 시스템 (bdpipe 방식)
# =============================================================================

def generate_backup_token(email: str) -> str:
    """백업용 간단한 토큰 생성 (bdpipe 방식)"""
    timestamp = str(int(time.time()))
    raw_token = f"{email}_{timestamp}_voc_backup"
    return hashlib.md5(raw_token.encode()).hexdigest()[:16]

def validate_backup_token(token: str, email: str) -> bool:
    """백업 토큰 검증 (bdpipe 방식)"""
    if not token or len(token) != 16:
        return False
    # 간단한 검증 (실제 운영에서는 더 강화 필요)
    return True

def setup_url_backup_session(user_info: Dict[str, Any]):
    """로그인 성공시 URL에 백업 토큰 설정"""
    backup_token = generate_backup_token(user_info['email'])
    
    # URL 파라미터에 백업 정보 저장
    st.query_params.update({
        "backup_token": backup_token,
        "backup_user": user_info['email']
    })

def restore_from_url_backup() -> Optional[Dict[str, Any]]:
    """URL 백업에서 세션 복원"""
    query_params = st.query_params
    if 'backup_token' in query_params and 'backup_user' in query_params:
        backup_token = query_params['backup_token']
        backup_user = query_params['backup_user']
        
        if validate_backup_token(backup_token, backup_user):
            # DB에서 직접 사용자 정보 조회
            user_info = get_user_info_from_db(backup_user)
            if user_info and user_info['auth_level'] > 0:
                return user_info
    return None

# API 호출 헬퍼 함수들
def get_auth_headers():
    """인증 헤더 생성"""
    if 'session_token' in st.session_state:
        return {"Authorization": f"Bearer {st.session_state.session_token}"}
    return {}

def get_cookie_auth_headers():
    """쿠키 기반 인증 헤더 생성"""
    return {"Content-Type": "application/x-www-form-urlencoded"}

def login_locally(email: str, password: str):
    """로컬 DB에서 직접 로그인 (API 서버 불필요)"""
    try:
        # 1. 로컬 DB에서 인증 시도
        user_info = authenticate_user_locally(email, password)
        if user_info:
            return user_info
        
        # 2. 파일 기반 인증으로 폴백
        user_info = authenticate_user(email, password)
        if user_info:
            return user_info
        
        return None
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 로컬 로그인 실패: {e}")
        return None

def api_login_with_cookie(email: str, password: str):
    """쿠키 기반 로그인 API 호출 (기존 호환성 유지)"""
    try:
        # Form data로 전송
        data = {
            "username": email,  # OAuth2PasswordRequestForm은 username 필드를 사용
            "password": password
        }
        
        response = requests.post(
            f"{API_BASE_URL}/auth/login-cookie",
            data=data,
            headers=get_cookie_auth_headers(),
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            # 쿠키를 세션 쿠키로 저장 (브라우저 종료시 자동 삭제)
            if 'access_token' in result:
                # 세션 쿠키로 설정 (브라우저 종료시 자동 삭제됨)
                cookies.set_session_cookie('auth_token', result['access_token'])
                cookies.set_session_cookie('user_email', email)
                cookies.save()
            return result
        else:
            return None
    except Exception as e:
        return None

def verify_auth_locally():
    """API 서버 없이 로컬에서 인증 검증 (개선: 즉시 삭제 방지)"""
    try:
        # 로컬 쿠키에서 토큰 가져오기
        auth_token = cookies.get('auth_token')
        if not auth_token:
            return None

        # JWT 토큰을 로컬에서 검증
        user_info = verify_local_jwt_token(auth_token)
        if user_info:
            return user_info

        # JWT 토큰이 유효하지 않아도 쿠키는 즉시 삭제하지 않음
        # (파일 기반 세션 복원 등 다른 방법으로 재시도 가능하도록)
        if st.session_state.get('debug_mode', False):
            st.warning("⚠️ JWT 토큰 검증 실패. 다른 방법으로 세션 복원을 시도합니다.")
        return None

    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 로컬 인증 검증 실패: {e}")
        return None

def api_verify_cookie_auth():
    """쿠키 기반 인증 검증 API 호출 (개선: 즉시 삭제 방지)"""
    try:
        # 로컬 쿠키에서 토큰 가져오기
        auth_token = cookies.get('auth_token')
        if not auth_token:
            return None

        # 토큰을 헤더에 포함하여 검증 요청
        headers = {"Authorization": f"Bearer {auth_token}"}
        response = requests.get(
            f"{API_BASE_URL}/auth/me",
            headers=headers,
            timeout=5
        )

        if response.status_code == 200:
            return response.json()
        else:
            # API 인증 실패 시에도 쿠키는 즉시 삭제하지 않음
            # (로컬 DB 인증 등 다른 방법으로 재시도 가능하도록)
            if st.session_state.get('debug_mode', False):
                st.warning("⚠️ API 인증 검증 실패. 다른 방법으로 세션 복원을 시도합니다.")
            return None
    except Exception as e:
        # 네트워크 오류 등 예외 발생 시에도 쿠키는 유지
        return None

def api_logout_with_cookie():
    """쿠키 기반 로그아웃 API 호출"""
    try:
        # 서버에 로그아웃 요청 (쿠키 삭제 전에 먼저)
        auth_token = cookies.get('auth_token')
        if auth_token:
            headers = {"Authorization": f"Bearer {auth_token}"}
            try:
                requests.post(
                    f"{API_BASE_URL}/auth/logout",
                    headers=headers,
                    timeout=5
                )
            except:
                pass  # 네트워크 오류 시 무시하고 로컬 정리 진행

        # 모든 관련 쿠키 완전 삭제
        try:
            cookies.delete('auth_token')
            cookies.delete('user_email')
            # 암호화 키 매개변수 쿠키도 삭제하여 완전 초기화
            cookies.delete('EncryptedCookieManager.key_params')
            cookies.save()
        except:
            pass

        # 세션 상태도 완전 초기화
        if 'session_token' in st.session_state:
            del st.session_state['session_token']
        if 'current_user' in st.session_state:
            del st.session_state['current_user']
        if 'user_level' in st.session_state:
            del st.session_state['user_level']

        return True
    except Exception as e:
        return False

def api_get(endpoint):
    """GET API 호출"""
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", headers=get_auth_headers(), timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            # API 호출 실패 시 조용히 처리 (에러 메시지 표시하지 않음)
            return None
    except Exception as e:
        # API 서버가 실행되지 않은 경우 조용히 처리
        return None

def api_post(endpoint, data):
    """POST API 호출"""
    try:
        response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, headers=get_auth_headers(), timeout=5)
        if response.status_code in [200, 201]:
            return response.json()
        else:
            return None
    except Exception as e:
        return None

def api_patch(endpoint, data):
    """PATCH API 호출"""
    try:
        response = requests.patch(f"{API_BASE_URL}{endpoint}", json=data, headers=get_auth_headers(), timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        return None

def api_delete(endpoint):
    """DELETE API 호출"""
    try:
        response = requests.delete(f"{API_BASE_URL}{endpoint}", headers=get_auth_headers(), timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        return None

# -----------------------------------------------------------------------------
# Modal compatibility helper (Streamlit versions without st.modal)
# -----------------------------------------------------------------------------
def _modal_ctx(title: str, key: str = "modal"):
    """Return a context manager for a modal-like container.
    Uses st.modal if available; otherwise falls back to a bordered container.
    """
    if hasattr(st, "modal"):
        return st.modal(title, key=key)
    # Fallback: container with a title - 숨김 처리
    st.markdown(f"### {title}")
    return st.container(border=True)

def get_password_hash(password: str) -> str:
    """간단한 비밀번호 해싱 (개발용)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """비밀번호 검증"""
    return get_password_hash(plain_password) == hashed_password

def generate_local_jwt_token(email: str, user_info: Dict[str, Any]) -> str:
    """로컬에서 JWT 토큰 생성 (서명 없이)"""
    import base64
    import json
    
    # 헤더
    header = {
        "alg": "none",
        "typ": "JWT"
    }
    
    # 페이로드
    payload = {
        "sub": email,
        "username": user_info.get("username", ""),
        "auth_level": user_info.get("auth_level", 0),
        "department": user_info.get("department", "전략팀"),
        "iat": int(time.time()),
        "exp": int(time.time()) + (7 * 24 * 60 * 60)  # 7일
    }
    
    # Base64 인코딩
    header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    # JWT 토큰 생성 (서명 없음)
    token = f"{header_b64}.{payload_b64}."
    
    return token

def generate_session_token(email: str) -> str:
    """세션 토큰 생성 (개선된 버전) - 기존 호환성 유지"""
    import base64
    
    # 24시간 후 만료
    expire_time = int(time.time()) + (24 * 60 * 60)
    token_data = f"{email}:{expire_time}:voc_session"
    
    # Base64로 인코딩하여 토큰 생성
    token_b64 = base64.b64encode(token_data.encode()).decode()
    return token_b64

def verify_local_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """로컬 JWT 토큰 검증 (API 서버 불필요)"""
    try:
        import base64
        import json
        
        if not token:
            return None
        
        # JWT 토큰 파싱
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # 페이로드 디코딩
        payload = parts[1]
        # 패딩 추가
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.b64decode(payload)
        token_data = json.loads(decoded)
        
        # 만료 시간 확인
        if time.time() > token_data.get('exp', 0):
            return None
        
        # 사용자 정보를 로컬 DB에서 조회
        email = token_data.get('sub', '')
        user_info = get_user_info_from_db(email)
        
        if user_info:
            return {
                'email': email,
                'username': token_data.get('username', ''),
                'auth_level': token_data.get('auth_level', 0),
                'department': token_data.get('department', '전략팀')
            }
        
        return None
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: JWT 토큰 검증 실패: {e}")
        return None

def validate_session_token(token: str, email: str) -> bool:
    """세션 토큰 검증 (개선된 버전)"""
    try:
        import base64

        if not token or not email:
            return False

        # Base64 디코딩 시도
        try:
            token_data = base64.b64decode(token.encode()).decode()
            parts = token_data.split(':')

            if len(parts) == 3:
                token_email, expire_str, session_type = parts

                # 이메일 확인
                if token_email != email:
                    return False

                # 만료 시간 확인
                expire_time = int(expire_str)
                current_time = time.time()
                if current_time > expire_time:
                    return False

                # 세션 타입 확인
                if session_type != "voc_session":
                    return False

                return True
        except:
            # Base64 디코딩 실패 시 기존 방식으로 폴백
            pass

        # 기존 방식: 세션 토큰이 세션 상태에 저장된 것과 일치하는지 확인
        if 'session_token' in st.session_state:
            return st.session_state.session_token == token
        
        # 기본 검증
        return len(token) >= 8  # 최소 길이 확인

    except Exception:
        return False

def update_session_state(user_info: Dict[str, Any]):
    """세션 상태 업데이트"""
    st.session_state.user_email = user_info.get('email', st.session_state.get('user_email', ''))
    st.session_state.username = user_info.get('username', st.session_state.get('username', ''))
    st.session_state.auth_level = user_info.get('auth_level', st.session_state.get('auth_level', 0))
    st.session_state.profile_department = user_info.get('department', st.session_state.get('profile_department', '전략팀'))
    st.session_state.logged_in = True

def clear_session_state():
    """세션 상태 완전 초기화"""
    for key in ['logged_in', 'user_email', 'username', 'auth_level', 'session_token', 'profile_department']:
        if key in st.session_state:
            del st.session_state[key]

def auto_login_attempt() -> bool:
    """로그인되지 않은 상태에서 자동 로그인 시도"""
    # URL 백업에서 복원 시도
    backup_info = restore_from_url_backup()
    if backup_info:
        update_session_state(backup_info)
        return True
    return False

def check_session_validity():
    """개선된 세션 상태 확인 - 성능 최적화 버전"""

    # 이미 로그인 상태라면 기본 검증만 수행
    if st.session_state.get('logged_in', False):
        # 세션 토큰과 이메일이 있으면 유효하다고 간주 (빠름)
        token = st.session_state.get('session_token')
        email = st.session_state.get('user_email')
        if token and email:
            return True

        # 토큰이 없으면 쿠키에서 복원 시도 (느림)
        user_info = verify_auth_locally()
        if user_info:
            update_session_state(user_info)
            return True

        # 모든 방법 실패시 로그아웃
        clear_session_state()
        return False

    # 로그인되지 않은 상태에서 자동 로그인 시도
    return auto_login_attempt()

def save_session_to_localStorage():
    """세션을 로컬 파일에 저장"""
    if st.session_state.get('logged_in', False):
        session_data = {
            'user_email': st.session_state.get('user_email', ''),
            'username': st.session_state.get('username', ''),
            'auth_level': st.session_state.get('auth_level', 0),
            'session_token': st.session_state.get('session_token', ''),
            'profile_department': st.session_state.get('profile_department', '전략팀'),
            'timestamp': time.time()
        }

        session_dir = os.path.join(BASE_DIR, ".sessions")
        os.makedirs(session_dir, exist_ok=True)

        # 사용자별 세션 파일
        session_file = os.path.join(session_dir, f"session_{hashlib.md5(session_data['user_email'].encode()).hexdigest()}.json")

        try:
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            pass  # 조용히 처리

def load_session_from_localStorage():
    """로컬 파일에서 최신 세션 로드"""
    session_dir = os.path.join(BASE_DIR, ".sessions")
    if not os.path.exists(session_dir):
        return None

    try:
        # 모든 세션 파일 검색
        session_files = [f for f in os.listdir(session_dir) if f.startswith("session_") and f.endswith(".json")]

        if not session_files:
            return None

        # 가장 최근 세션 파일 찾기
        latest_session = None
        latest_time = 0

        for session_file in session_files:
            file_path = os.path.join(session_dir, session_file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    session_data = json.load(f)

                # 24시간 이내 세션만 유효
                session_time = session_data.get('timestamp', 0)
                if time.time() - session_time < 24 * 60 * 60:  # 24시간
                    if session_time > latest_time:
                        latest_time = session_time
                        latest_session = session_data
                else:
                    # 만료된 세션 파일 삭제
                    os.remove(file_path)
            except Exception:
                # 손상된 파일 삭제
                try:
                    os.remove(file_path)
                except Exception:
                    pass

        return latest_session
    except Exception:
        return None

def clear_localStorage():
    """로컬 세션 파일 제거"""
    session_dir = os.path.join(BASE_DIR, ".sessions")
    if os.path.exists(session_dir):
        try:
            # 현재 사용자의 세션 파일만 삭제
            if st.session_state.get('user_email'):
                email_hash = hashlib.md5(st.session_state['user_email'].encode()).hexdigest()
                session_file = os.path.join(session_dir, f"session_{email_hash}.json")
                if os.path.exists(session_file):
                    os.remove(session_file)
        except Exception:
            pass

def initialize_session_from_cookie():
    """페이지 로드 시 쿠키에서 세션 복원 시도 (로컬 우선)"""
    # 이미 로그인된 상태라면 스킵
    if st.session_state.get('logged_in', False):
        return False

    # 1. 로컬 쿠키 검증 (API 서버 불필요)
    user_info = verify_auth_locally()
    if user_info:
        # 세션 복원
        st.session_state.logged_in = True
        st.session_state.user_email = user_info.get('email', '')
        st.session_state.username = user_info.get('username', '')
        st.session_state.auth_level = user_info.get('auth_level', 0)
        st.session_state.profile_department = user_info.get('department', '전략팀')

        # 세션 토큰도 생성 (기존 로직과의 호환성을 위해)
        token = generate_session_token(st.session_state.user_email)
        st.session_state.session_token = token

        # 파일 기반 세션도 저장 (백업용)
        save_session_to_localStorage()

        return True
    
    # 2. API 서버 쿠키 검증 (백업용)
    try:
        user_info = api_verify_cookie_auth()
        if user_info:
            # 세션 복원
            st.session_state.logged_in = True
            st.session_state.user_email = user_info.get('email', '')
            st.session_state.username = user_info.get('username', '')
            st.session_state.auth_level = user_info.get('auth_level', 0)
            st.session_state.profile_department = user_info.get('department', '전략팀')

            # 세션 토큰도 생성 (기존 로직과의 호환성을 위해)
            token = generate_session_token(st.session_state.user_email)
            st.session_state.session_token = token

            # 파일 기반 세션도 저장 (백업용)
            save_session_to_localStorage()

            return True
    except Exception:
        # API 서버 연결 실패 시 조용히 넘어감
        pass
    
    return False

def initialize_session_from_localStorage():
    """페이지 로드 시 파일에서 세션 복원 시도 (개선: 쿠키 재동기화)"""
    if 'session_restored' not in st.session_state and not st.session_state.get('logged_in', False):
        st.session_state.session_restored = True

        # 로컬 파일에서 세션 복원
        session_data = load_session_from_localStorage()
        if session_data:
            token = session_data.get('session_token', '')
            email = session_data.get('user_email', '')

            if token and email and validate_session_token(token, email):
                # 세션 복원
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.session_state.username = session_data.get('username', '')
                st.session_state.auth_level = session_data.get('auth_level', 0)
                st.session_state.session_token = token
                st.session_state.profile_department = session_data.get('profile_department', '전략팀')

                # 쿠키도 재설정 (동기화) - 중요!
                try:
                    cookies.set_persistent_cookie('auth_token', token, expires_days=7)
                    cookies.set_persistent_cookie('user_email', email, expires_days=7)
                    cookies.save()
                except Exception as e:
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🐛 DEBUG: 쿠키 재설정 실패: {e}")

                return True
    return False

def auto_login_from_url():
    """URL 파라미터에서 자동 로그인 시도 (비활성화)"""
    # URL 파라미터 기반 자동 로그인을 비활성화하고 세션 상태만 사용
    return False

# 사용자 데이터 파일 경로를 모듈 디렉터리 기준으로 고정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DATA_FILE = os.path.join(BASE_DIR, "user_data.json")

def _default_users():
    # 시드 비밀번호는 DEFAULT_RESET_PW 환경변수로만 주입한다(코드에 실값 없음).
    seed_pw = DEFAULT_RESET_PW or os.urandom(8).hex()
    return {
        DEFAULT_ADMIN_EMAIL: {
            "username": "admin",
            "password_hash": get_password_hash(seed_pw),
            "auth_level": 5,
            "is_active": True,
            "department": "HR"
        },
        "user@example.com": {
            "username": "user",
            "password_hash": get_password_hash(seed_pw),
            "auth_level": 1,
            "is_active": True,
            "department": "전략팀"
        },
        "manager@example.com": {
            "username": "manager",
            "password_hash": get_password_hash(seed_pw),
            "auth_level": 3,
            "is_active": True,
            "department": "전략팀"
        }
    }

def load_users_from_file():
    """파일에서 사용자 데이터 로드. 없거나 손상 시 기본 생성 후 저장"""
    try:
        if os.path.exists(USER_DATA_FILE):
            with open(USER_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        st.warning(f"사용자 데이터 로드 중 문제 발생: {e}. 백업을 시도합니다.")
        # 손상 시 백업에서 복구 시도
        backup_path = USER_DATA_FILE + ".bak"
        if os.path.exists(backup_path):
            try:
                with open(backup_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                save_users_to_file(data)
                return data
            except Exception as e2:
                st.error(f"백업 복구 실패: {e2}")

    # 최초 생성 또는 복구 실패 시 기본값 쓰기
    data = _default_users()
    save_users_to_file(data)
    return data

def save_users_to_file(users_data):
    """파일에 사용자 데이터 저장 (원자적 쓰기 + 백업)"""
    try:
        os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)

        # 임시 파일에 먼저 기록
        dir_name = os.path.dirname(USER_DATA_FILE) or BASE_DIR
        fd, temp_path = tempfile.mkstemp(prefix="user_data_", suffix=".tmp", dir=dir_name)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                json.dump(users_data, tmp, ensure_ascii=False, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())

            # 기존 파일 백업
            if os.path.exists(USER_DATA_FILE):
                backup_path = USER_DATA_FILE + ".bak"
                try:
                    with open(USER_DATA_FILE, 'r', encoding='utf-8') as src, open(backup_path, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                except Exception as be:
                    st.warning(f"백업 생성 실패: {be}")

            # 원자적 교체
            os.replace(temp_path, USER_DATA_FILE)
        finally:
            # temp_path가 남아있으면 정리
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
    except Exception as e:
        st.error(f"사용자 데이터 저장 실패: {e}")

def get_temp_users():
    """사용자 데이터 가져오기 (파일 기반)"""
    if 'temp_users' not in st.session_state:
        st.session_state.temp_users = load_users_from_file()
    return st.session_state.temp_users

def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """사용자 인증"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    if not user:
        return None
    
    if not verify_password(password, user["password_hash"]):
        return None
    
    if not user["is_active"]:
        return None
    
    if user["auth_level"] == 0:
        return None
    
    return {
        "email": email,
        "username": user["username"],
        "auth_level": user["auth_level"],
        "authenticated": True,
        "department": user.get("department", "전략팀")
    }

def check_password_reset_needed(email: str, password: str) -> bool:
    """비밀번호 재설정이 필요한지 확인"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    if not user:
        return False
    if not DEFAULT_RESET_PW:
        return False
    return verify_password(DEFAULT_RESET_PW, user["password_hash"]) and password == DEFAULT_RESET_PW

def update_user_password(email: str, new_password: str) -> bool:
    """사용자 비밀번호 업데이트"""
    temp_users = get_temp_users()
    if email in temp_users:
        temp_users[email]["password_hash"] = get_password_hash(new_password)
        save_users_to_file(temp_users)  # 파일에 저장
        return True
    return False

def register_user(email: str, username: str, password: str) -> bool:
    """사용자 회원가입"""
    temp_users = get_temp_users()
    if email in temp_users:
        return False
    
    temp_users[email] = {
        "username": username,
        "password_hash": get_password_hash(password),
        "auth_level": 0,  # 승인 대기
        "is_active": True
    }
    save_users_to_file(temp_users)  # 파일에 저장
    return True

def get_users_with_reset_permission(user_auth_level: int):
    """비밀번호 초기화 권한이 있는 사용자 목록"""
    temp_users = get_temp_users()
    return [
        {"email": email, "username": data["username"], "auth_level": data["auth_level"]}
        for email, data in temp_users.items()
        if data["auth_level"] >= 3 and data["auth_level"] >= user_auth_level and data["is_active"]
    ]

def reset_user_password(email: str, username: str, actor_email: str) -> bool:
    """사용자 비밀번호 초기화"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    actor = temp_users.get(actor_email)
    
    if not user or not actor:
        return False
    
    if user["username"] != username:
        return False
    
    if actor["auth_level"] < 3 or actor["auth_level"] < user["auth_level"]:
        return False

    if not DEFAULT_RESET_PW:
        return False

    temp_users[email]["password_hash"] = get_password_hash(DEFAULT_RESET_PW)
    save_users_to_file(temp_users)  # 파일에 저장
    return True

def password_reset_page():
    """비밀번호 재설정 페이지"""
    st.subheader("🔑 새 비밀번호 설정")
    st.warning("보안을 위해 새로운 비밀번호를 설정해 주세요.")
    
    with st.form("password_reset_form"):
        new_password = st.text_input("새 비밀번호 (6자리 이상)", type="password")
        confirm_password = st.text_input("비밀번호 확인", type="password")
        
        if st.form_submit_button("비밀번호 설정"):
            if len(new_password) < 6:
                st.error("비밀번호는 6자리 이상이어야 합니다.")
            elif new_password != confirm_password:
                st.error("비밀번호가 일치하지 않습니다.")
            elif DEFAULT_RESET_PW and new_password == DEFAULT_RESET_PW:
                st.error("보안을 위해 기본 초기화 비밀번호는 사용할 수 없습니다.")
            else:
                if update_user_password(st.session_state.user_email, new_password):
                    # 비밀번호 변경 후 자동 로그인 처리
                    temp_users = get_temp_users()
                    user = temp_users.get(st.session_state.user_email)
                    
                    st.session_state.logged_in = True
                    st.session_state.username = user["username"]
                    st.session_state.auth_level = user["auth_level"]
                    st.session_state.password_reset_needed = False
                    
                    # 세션 토큰 생성
                    token = generate_session_token(st.session_state.user_email)
                    st.session_state.session_token = token
                    
                    st.success("비밀번호가 성공적으로 변경되었습니다!")
                    st.rerun()
                else:
                    st.error("비밀번호 변경에 실패했습니다.")

def login_page():
    """로그인 페이지"""
    st.title("🏢 VOC Management System")
    
    tab1, tab2, tab3 = st.tabs(["로그인", "회원가입", "비밀번호 초기화"])
    
    with tab1:
        st.subheader("로그인")
        
        # 재인증 모달과 동일한 방식으로 st.form() 사용
        with st.form("login_form"):
            email = st.text_input("이메일", key="login_email")
            password = st.text_input("비밀번호", type="password", key="login_password")
            
            # form_submit_button 사용 (엔터키 자동 지원)
            submitted = st.form_submit_button("로그인")
            
            if submitted:
                if email and password:
                    # 로컬 인증 시도 (API 서버 불필요)
                    user_info = login_locally(email, password)
                    
                    if user_info and user_info.get("authenticated"):
                        # 세션 상태 설정
                        st.session_state.logged_in = True
                        st.session_state.user_email = email
                        st.session_state.username = user_info["username"]
                        st.session_state.auth_level = user_info["auth_level"]
                        st.session_state.profile_department = user_info.get("department", "전략팀")
                        
                        # 로컬 JWT 토큰 생성
                        jwt_token = generate_local_jwt_token(email, user_info)
                        st.session_state.session_token = jwt_token
                        
                        # 영구 쿠키에 저장 (7일간 유지)
                        cookies.set_persistent_cookie('auth_token', jwt_token, expires_days=7)
                        cookies.set_persistent_cookie('user_email', email, expires_days=7)
                        cookies.save()
                        
                        # URL 백업 시스템 설정
                        setup_url_backup_session(user_info)
                        
                        # 세션을 파일에 저장 (백업용)
                        save_session_to_localStorage()
                        
                        st.success("로그인 성공!")
                        st.rerun()
                    else:
                        # 비밀번호 재설정 필요 확인
                        if check_password_reset_needed(email, password):
                            st.session_state.user_email = email
                            st.session_state.password_reset_needed = True
                            st.rerun()
                            return
                        
                        st.error("잘못된 이메일 또는 비밀번호입니다.")
                else:
                    st.error("이메일과 비밀번호를 입력하세요.")
    
    with tab2:
        st.subheader("회원가입")
        reg_email = st.text_input("이메일", key="reg_email")
        reg_username = st.text_input("사용자명", key="reg_username")
        reg_password = st.text_input("비밀번호", type="password", key="reg_password")
        
        if st.button("회원가입 신청", key="register_btn"):
            if reg_email and reg_username and reg_password:
                if register_user(reg_email, reg_username, reg_password):
                    st.success("회원가입 신청이 완료되었습니다. 관리자 승인을 기다려주세요.")
                else:
                    st.error("이미 존재하는 이메일입니다.")
            else:
                st.error("모든 필드를 입력하세요.")
    
    with tab3:
        st.subheader("비밀번호 초기화 요청")
        reset_email = st.text_input("이메일", key="reset_email")
        reset_username = st.text_input("사용자명", key="reset_username")
        
        if st.button("초기화 요청", key="reset_request_btn"):
            if reset_email and reset_username:
                temp_users = get_temp_users()
                user = temp_users.get(reset_email)
                if user and user["username"] == reset_username:
                    st.success("비밀번호 초기화 요청이 접수되었습니다.")
                    
                    # 권한이 있는 사용자 목록 표시
                    reset_users = get_users_with_reset_permission(user["auth_level"])
                    if reset_users:
                        st.write("**초기화 권한이 있는 사용자:**")
                        for reset_user in reset_users:
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                st.write(f"- {reset_user['username']} ({reset_user['email']}) - Level {reset_user['auth_level']}")
                            with col2:
                                if st.button("초기화", key=f"reset_{reset_user['email']}"):
                                    if reset_user_password(reset_email, reset_username, reset_user['email']):
                                        st.success("비밀번호가 기본 비밀번호로 초기화되었습니다.")
                                        st.rerun()
                                    else:
                                        st.error("초기화에 실패했습니다.")
                    else:
                        st.warning("초기화 권한이 있는 사용자가 없습니다.")
                else:
                    st.error("이메일 또는 사용자명이 올바르지 않습니다.")
            else:
                st.error("이메일과 사용자명을 입력하세요.")

def debug_session_status():
    """디버그용 세션 상태 출력 (최적화: 디버그 모드일 때만 실행)"""
    if not st.session_state.get('debug_mode', False):
        return  # 디버그 모드가 아니면 즉시 리턴

    with st.sidebar:
        st.markdown("### 🐛 디버그 정보")

        # 세션 상태 정보만 표시 (가볍게)
        st.json({
            "logged_in": st.session_state.get('logged_in', False),
            "user_email": st.session_state.get('user_email', 'None'),
            "auth_level": st.session_state.get('auth_level', 0),
            "cookie_ready": cookies.ready(),
        })

        # 디버그 모드 토글 버튼
        if st.button("🔴 디버그 모드 끄기"):
            st.session_state['debug_mode'] = False
            st.rerun()

def voc_table_page():
    """VOC 테이블 페이지"""
    st.title("📊 VOC Management Dashboard")

    # 디버그 정보 표시
    debug_session_status()
    
    # 탭 생성
    tab1, tab2, tab3 = st.tabs(["📋 VOC 목록", "✏️ 테이블 편집", "📊 통계"])
    
    with tab1:
        show_voc_list()
    
    with tab2:
        show_table_editor()
    
    with tab3:
        show_voc_statistics()

def show_voc_list():
    """VOC 목록 표시"""
    # 기존 VOC 목록 표시 로직을 여기로 이동
    if st.session_state.get('auth_level', 0) >= 2:
        # lv2 이상 사용자는 모든 탭 표시
        tab1, tab2, tab3, tab4 = st.tabs(["📋 VOC", "🏢 회사", "👥 연락처", "📁 프로젝트"])
        
        with tab1:
            _render_voc_tab()
        
        with tab2:
            _render_company_tab()
        
        with tab3:
            _render_contact_tab()
        
        with tab4:
            _render_project_tab()
    else:
        # lv1 사용자는 VOC만 표시
        _render_voc_tab()

def show_table_editor():
    """테이블 편집 기능"""
    st.subheader("✏️ 테이블 편집")
    
    # 사용자 권한 확인
    user_level = st.session_state.get('auth_level', 0)
    st.info(f"현재 권한 레벨: {user_level} | 편집 가능한 데이터: {'본인 데이터만' if user_level <= 2 else '자기 레벨 이하 유저 데이터'}")
    
    # 편집할 테이블 선택
    table_type = st.selectbox(
        "편집할 테이블을 선택하세요:",
        ["VOC", "회사", "연락처", "프로젝트"],
        key="table_editor_type"
    )
    
    if table_type == "VOC":
        edit_voc_table()
    elif table_type == "회사":
        edit_company_table()
    elif table_type == "연락처":
        edit_contact_table()
    elif table_type == "프로젝트":
        edit_project_table()

def show_voc_statistics():
    """VOC 통계 표시"""
    st.subheader("📊 VOC 통계")
    
    # 관리자 기능
    user_level = st.session_state.get('auth_level', 0)
    if user_level >= 4:
        st.subheader("🔧 관리자 기능")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("👥 더미 사용자 생성", type="secondary"):
                create_dummy_users()
        
        with col2:
            if st.button("📊 샘플 데이터 생성", type="secondary"):
                create_sample_data()
        
        with col3:
            if st.button("🔄 데이터 새로고침", type="secondary"):
                st.rerun()
    
    st.info("통계 기능은 추후 구현 예정입니다.")

def create_dummy_users():
    """더미 사용자 생성"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{API_BASE_URL}/admin/setup-dummy-users",
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            st.success(result.get('message', '더미 사용자가 생성되었습니다.'))
            if 'created_users' in result and result['created_users']:
                st.write("생성된 사용자:")
                for user in result['created_users']:
                    st.write(f"- {user['username']} ({user['email']}) - Level {user['auth_level']}")
        else:
            st.error(f"더미 사용자 생성 실패: {response.text}")
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")

def create_sample_data():
    """샘플 데이터 생성"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{API_BASE_URL}/admin/setup-sample-data",
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            st.success(result.get('message', '샘플 데이터가 생성되었습니다.'))
            if 'created_data' in result:
                data = result['created_data']
                st.write(f"생성된 데이터: 회사 {data['companies']}개, 연락처 {data['contacts']}개, 프로젝트 {data['projects']}개, VOC {data['vocs']}개")
        else:
            st.error(f"샘플 데이터 생성 실패: {response.text}")
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")

def edit_voc_table():
    """VOC 테이블 편집"""
    st.subheader("📋 VOC 테이블 편집")
    
    # VOC 데이터 로드
    try:
        voc_data = load_voc_data()
        if not voc_data:
            st.warning("VOC 데이터를 불러올 수 없습니다.")
            return
        
        # 권한에 따른 데이터 필터링
        user_level = st.session_state.get('auth_level', 0)
        user_id = st.session_state.get('user_id', 0)
        
        if user_level <= 2:
            # 레벨 2 이하: 본인 데이터만 표시
            filtered_data = [voc for voc in voc_data if voc.get('assignee_user_id') == user_id]
            st.info(f"본인 데이터만 표시됩니다. (총 {len(filtered_data)}개)")
        else:
            # 레벨 3 이상: 모든 데이터 표시
            filtered_data = voc_data
            st.info(f"모든 데이터가 표시됩니다. (총 {len(filtered_data)}개)")
        
        if not filtered_data:
            st.warning("편집 가능한 VOC 데이터가 없습니다.")
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame(filtered_data)
        
        # 편집 가능한 컬럼 설정
        column_config = {
            "ID": st.column_config.NumberColumn("ID", width=50, disabled=True),
            "날짜": st.column_config.DateColumn("날짜", width=100),
            "내용": st.column_config.TextColumn("내용", width=300),
            "액션아이템": st.column_config.TextColumn("액션아이템", width=200),
            "마감일": st.column_config.DateColumn("마감일", width=100),
            "상태": st.column_config.SelectboxColumn(
                "상태", 
                options=["pending", "in_progress", "done", "on_hold"],
                width=100
            ),
            "우선순위": st.column_config.SelectboxColumn(
                "우선순위",
                options=["low", "medium", "high", "urgent"],
                width=100
            ),
            "담당자": st.column_config.TextColumn("담당자", width=100, disabled=True),
            "회사명": st.column_config.TextColumn("회사명", width=150, disabled=True),
            "연락처": st.column_config.TextColumn("연락처", width=100, disabled=True),
            "프로젝트명": st.column_config.TextColumn("프로젝트명", width=150, disabled=True),
            "AI요약": st.column_config.TextColumn("AI요약", width=200, disabled=True)
        }
        
        # 데이터 편집기 표시
        edited_df = st.data_editor(
            df,
            column_config=column_config,
            num_rows="dynamic",
            use_container_width=True,
            key="voc_editor"
        )
        
        # 저장 버튼
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("💾 변경사항 저장", type="primary"):
                save_voc_changes(edited_df, df)
        
    except Exception as e:
        st.error(f"VOC 데이터 로드 중 오류가 발생했습니다: {str(e)}")

def edit_company_table():
    """회사 테이블 편집"""
    st.subheader("🏢 회사 테이블 편집")
    
    # 회사 데이터 로드
    try:
        company_data = load_company_data()
        if not company_data:
            st.warning("회사 데이터를 불러올 수 없습니다.")
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame(company_data)
        
        # 편집 가능한 컬럼 설정
        column_config = {
            "ID": st.column_config.NumberColumn("ID", width=50, disabled=True),
            "회사명": st.column_config.TextColumn("회사명", width=200),
            "도메인": st.column_config.TextColumn("도메인", width=150),
            "매출": st.column_config.TextColumn("매출", width=100),
            "직원수": st.column_config.NumberColumn("직원수", width=80),
            "국가": st.column_config.TextColumn("국가", width=100),
            "생성일": st.column_config.DatetimeColumn("생성일", width=120, disabled=True),
            "수정일": st.column_config.DatetimeColumn("수정일", width=120, disabled=True)
        }
        
        # 데이터 편집기 표시
        edited_df = st.data_editor(
            df,
            column_config=column_config,
            num_rows="dynamic",
            use_container_width=True,
            key="company_editor"
        )
        
        # 저장 버튼
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("💾 변경사항 저장", type="primary"):
                save_company_changes(edited_df, df)
        
    except Exception as e:
        st.error(f"회사 데이터 로드 중 오류가 발생했습니다: {str(e)}")

def edit_contact_table():
    """연락처 테이블 편집"""
    st.subheader("👥 연락처 테이블 편집")
    
    # 연락처 데이터 로드
    try:
        contact_data = load_contact_data()
        if not contact_data:
            st.warning("연락처 데이터를 불러올 수 없습니다.")
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame(contact_data)
        
        # 편집 가능한 컬럼 설정
        column_config = {
            "ID": st.column_config.NumberColumn("ID", width=50, disabled=True),
            "이름": st.column_config.TextColumn("이름", width=100),
            "직책": st.column_config.TextColumn("직책", width=100),
            "이메일": st.column_config.TextColumn("이메일", width=200),
            "전화번호": st.column_config.TextColumn("전화번호", width=120),
            "메모": st.column_config.TextColumn("메모", width=200),
            "회사명": st.column_config.TextColumn("회사명", width=150, disabled=True),
            "생성일": st.column_config.DatetimeColumn("생성일", width=120, disabled=True),
            "수정일": st.column_config.DatetimeColumn("수정일", width=120, disabled=True)
        }
        
        # 데이터 편집기 표시
        edited_df = st.data_editor(
            df,
            column_config=column_config,
            num_rows="dynamic",
            use_container_width=True,
            key="contact_editor"
        )
        
        # 저장 버튼
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("💾 변경사항 저장", type="primary"):
                save_contact_changes(edited_df, df)
        
    except Exception as e:
        st.error(f"연락처 데이터 로드 중 오류가 발생했습니다: {str(e)}")

def edit_project_table():
    """프로젝트 테이블 편집"""
    st.subheader("📁 프로젝트 테이블 편집")
    
    # 프로젝트 데이터 로드
    try:
        project_data = load_project_data()
        if not project_data:
            st.warning("프로젝트 데이터를 불러올 수 없습니다.")
            return
        
        # 데이터프레임 생성
        df = pd.DataFrame(project_data)
        
        # 편집 가능한 컬럼 설정
        column_config = {
            "ID": st.column_config.NumberColumn("ID", width=50, disabled=True),
            "프로젝트명": st.column_config.TextColumn("프로젝트명", width=200),
            "분야": st.column_config.TextColumn("분야", width=100),
            "대상앱": st.column_config.TextColumn("대상앱", width=150),
            "AI모델": st.column_config.TextColumn("AI모델", width=150),
            "성능": st.column_config.TextColumn("성능", width=100),
            "전력": st.column_config.TextColumn("전력", width=100),
            "폼팩터": st.column_config.TextColumn("폼팩터", width=100),
            "메모리": st.column_config.TextColumn("메모리", width=100),
            "가격": st.column_config.TextColumn("가격", width=100),
            "요구사항": st.column_config.TextColumn("요구사항", width=200),
            "경쟁사": st.column_config.TextColumn("경쟁사", width=150),
            "결과": st.column_config.TextColumn("결과", width=150),
            "근본원인": st.column_config.TextColumn("근본원인", width=150),
            "회사명": st.column_config.TextColumn("회사명", width=150, disabled=True),
            "생성일": st.column_config.DatetimeColumn("생성일", width=120, disabled=True),
            "수정일": st.column_config.DatetimeColumn("수정일", width=120, disabled=True)
        }
        
        # 데이터 편집기 표시
        edited_df = st.data_editor(
            df,
            column_config=column_config,
            num_rows="dynamic",
            use_container_width=True,
            key="project_editor"
        )
        
        # 저장 버튼
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("💾 변경사항 저장", type="primary"):
                save_project_changes(edited_df, df)
        
    except Exception as e:
        st.error(f"프로젝트 데이터 로드 중 오류가 발생했습니다: {str(e)}")

    # 상단 사용자 정보 (우측 정렬, 버튼 간 간격 축소)
    top_left, top_settings, top_logout = st.columns([6.8, 1.0, 1.4])
    with top_left:
        # 디버그 모드 토글 추가
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 **디버그 모드** | 안녕하세요, **{st.session_state.username}**님! (Level {st.session_state.auth_level})")
        else:
            st.write(f"안녕하세요, **{st.session_state.username}**님! (Level {st.session_state.auth_level})")
    with top_settings:
        # 수평 오프셋을 위한 서브 컬럼 구성 (약 50px 여백 근사)
        sub_spacer, sub_btn = st.columns([0.45, 0.55])
        with sub_btn:
            if st.button("⚙️ 설정"):
                st.session_state["show_settings_modal"] = True
    with top_logout:
        # 로그아웃 버튼도 동일하게 약 40px 오른쪽으로 오프셋
        lo_spacer, lo_btn = st.columns([0.35, 0.65])
        with lo_btn:
            if st.button("🚪 로그아웃"):
                # 쿠키 기반 로그아웃 시도
                api_logout_with_cookie()
                
                # localStorage 세션 삭제
                clear_localStorage()
                
                # URL 백업 파라미터 정리 (새로 추가)
                st.query_params.clear()
                
                # 세션 상태 완전 초기화
                keys_to_remove = [
                    'logged_in', 'user_email', 'username', 'auth_level', 
                    'session_token', 'profile_department', 'password_reset_needed',
                    'show_settings_modal', 'show_reauth_modal', 'show_edit_profile_modal',
                    'show_user_mgmt_modal', 'reauth_context', 'edit_mode'
                ]
                for key in keys_to_remove:
                    if key in st.session_state:
                        del st.session_state[key]
                
                st.rerun()
    
    # 설정 모달 표시 (조건부 렌더링)
    if st.session_state.get("show_settings_modal", False):
        with _modal_ctx("설정", key="settings_modal"):
            _render_settings_modal_content()
    else:
        # 모달이 숨겨져 있을 때는 아무것도 렌더링하지 않음
        pass

    st.divider()
    
    # lv2 이상 사용자에게만 탭 표시
    if st.session_state.auth_level >= 2:
        # 편집 모드 상태 초기화
        if 'edit_mode' not in st.session_state:
            st.session_state.edit_mode = False
        
        # 편집 모드 토글 버튼
        if st.session_state.get('edit_mode', False):
            # 편집 모드일 때: 저장 버튼과 취소 버튼을 같은 줄에 배치
            button_col1, button_col2, button_col3 = st.columns([1, 1, 8])
            with button_col1:
                if st.button("💾 저장", type="primary"):
                    # 저장 로직 구현
                    _save_all_changes()
                    st.session_state.edit_mode = False
                    st.rerun()
            with button_col2:
                if st.button("❌ 취소"):
                    st.session_state.edit_mode = False
                    st.rerun()
        else:
            # 일반 모드일 때: 편집 버튼만 표시
            edit_col1, edit_col2 = st.columns([1, 9])
            with edit_col1:
                if st.button("✏️ 편집"):
                    st.session_state.edit_mode = True
                    st.rerun()
        
        # 탭 생성
        tab1, tab2, tab3, tab4 = st.tabs(["📋 VOC", "🏢 Company", "👥 Contact", "🚀 Project"])
        
        with tab1:
            _render_voc_tab()
        
        with tab2:
            _render_company_tab()
        
        with tab3:
            _render_contact_tab()
        
        with tab4:
            _render_project_tab()
    else:
        # lv1 사용자는 VOC만 표시
        _render_voc_tab()

def _render_voc_tab():
    """VOC 탭 렌더링"""
    st.subheader("VOC 목록")
    
    # 엑셀 스타일 필터링 안내
    st.info("💡 **엑셀 스타일 필터링**: 아래 필터를 사용하여 데이터를 필터링할 수 있습니다. 편집 모드에서는 데이터를 직접 수정할 수도 있습니다.")
    
    # 엑셀 스타일 테이블을 위한 CSS 주입
    st.markdown(
        """
        <style>
        /* st.dataframe과 st.dataeditor 헤더 가운데 정렬 */
        div[data-testid="stDataFrame"] thead tr th div,
        div[data-testid="stDataEditor"] thead tr th div {
            display: flex; justify-content: center; align-items: center;
        }
        div[data-testid="stDataFrame"] thead tr th,
        div[data-testid="stDataEditor"] thead tr th {
            text-align: center !important;
        }
        
        /* 버튼 텍스트 줄바꿈 방지 및 반응형 폰트/패딩 */
        div.stButton > button { white-space: nowrap; width: 100%; }
        @media (max-width: 1400px) {
            div.stButton > button { font-size: 0.9rem; padding: 0.35rem 0.7rem; }
        }
        @media (max-width: 1100px) {
            div.stButton > button { font-size: 0.8rem; padding: 0.3rem 0.6rem; }
        }
        
        /* 숨겨진 내용 완전히 숨기기 */
        .stExpander > div[data-testid="stExpanderContent"] {
            display: none !important;
        }
        .stExpander[aria-expanded="false"] > div[data-testid="stExpanderContent"] {
            display: none !important;
        }
        
        /* 엑셀 스타일 테이블 디자인 */
        div[data-testid="stDataEditor"] {
            border: 1px solid #d1d5db;
            border-radius: 6px;
            background-color: #ffffff;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        /* 편집 모드 시각적 개선 */
        div[data-testid="stDataEditor"]:has(input:not([disabled])) {
            border: 2px solid #ff6b6b;
            background-color: #fff5f5;
        }
        
        /* 필터링 가능한 헤더 스타일 */
        div[data-testid="stDataEditor"] thead tr th {
            background-color: #f8fafc !important;
            border-bottom: 2px solid #e5e7eb !important;
            font-weight: 600 !important;
        }
        
        /* 편집 중인 셀 하이라이트 */
        div[data-testid="stDataEditor"] input:focus,
        div[data-testid="stDataEditor"] select:focus {
            border: 2px solid #4ecdc4 !important;
            box-shadow: 0 0 5px rgba(78, 205, 196, 0.5) !important;
        }
        
        /* 행 호버 효과 */
        div[data-testid="stDataEditor"] tbody tr:hover {
            background-color: #f0f8ff !important;
        }
        
        /* 읽기 전용 모드 스타일 */
        div[data-testid="stDataEditor"][data-disabled="true"] {
            border: 1px solid #d1d5db;
            background-color: #f9fafb;
        }
        
        /* 필터 토글 스타일 */
        .stExpander[data-testid="stExpander"] {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        
        .stExpander[data-testid="stExpander"] > div[data-testid="stExpanderContent"] {
            background-color: #f8fafc;
            padding: 1rem;
        }
        
        /* 필터 입력 필드 스타일 */
        div[data-testid="stTextInput"] input,
        div[data-testid="stSelectbox"] select {
            border: 1px solid #d1d5db;
            border-radius: 4px;
        }
        
        /* 필터 버튼 스타일 */
        div[data-testid="stButton"] button {
            border-radius: 6px;
            font-weight: 500;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    
    # VOC 데이터 가져오기 (API 호출)
    voc_data = _get_voc_data()
    
    # 샘플 데이터가 있으면 추가
    if 'sample_voc_data' in st.session_state and st.session_state.sample_voc_data:
        voc_data.extend(st.session_state.sample_voc_data)
    
    # DataFrame으로 변환 후 컬럼 폭 조정
    import pandas as pd
    df = pd.DataFrame(voc_data)

    # 사용자 목록 가져오기 (필터링용)
    users = _get_users_list()
    user_names = [user.get('name', '') for user in users if user.get('name')]
    
    # 엑셀 스타일 컬럼별 필터 추가 (토글로 변경)
    if not df.empty:
        # 필터 토글
        with st.expander("🔍 컬럼별 필터", expanded=False):
            # 8개 컬럼에 맞춰 필터 배치 (2행으로 구성)
            filter_cols_row1 = st.columns(4)
            filter_cols_row2 = st.columns(4)
            
            with filter_cols_row1[0]:  # ID
                id_filter = st.text_input("ID", placeholder="ID 검색", key="filter_id")
            
            with filter_cols_row1[1]:  # 날짜
                date_filter = st.text_input("날짜", placeholder="날짜 검색", key="filter_date")
            
            with filter_cols_row1[2]:  # 회사
                company_options = ["전체"] + sorted(df['회사'].dropna().unique().tolist())
                company_filter = st.selectbox("회사", company_options, key="filter_company")
            
            with filter_cols_row1[3]:  # 내용
                content_filter = st.text_input("내용", placeholder="내용 검색", key="filter_content")
            
            with filter_cols_row2[0]:  # 상태
                status_options = ["전체"] + sorted(df['상태'].dropna().unique().tolist())
                status_filter = st.selectbox("상태", status_options, key="filter_status")
            
            with filter_cols_row2[1]:  # 우선순위
                priority_options = ["전체"] + sorted(df['우선순위'].dropna().unique().tolist())
                priority_filter = st.selectbox("우선순위", priority_options, key="filter_priority")
            
            with filter_cols_row2[2]:  # 담당자
                assignee_options = ["전체"] + sorted(df['담당자'].dropna().unique().tolist())
                assignee_filter = st.selectbox("담당자", assignee_options, key="filter_assignee")
            
            with filter_cols_row2[3]:  # 연관ID
                related_id_filter = st.text_input("연관ID", placeholder="연관ID 검색", key="filter_related_id")
            
            # 필터 제어 버튼
            st.markdown("---")
            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 8])
            with col_btn1:
                if st.button("🗑️ 필터 초기화", key="clear_all_filters"):
                    # 모든 필터 초기화
                    for key in ["filter_id", "filter_date", "filter_company", "filter_content", 
                               "filter_status", "filter_priority", "filter_assignee", "filter_related_id"]:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.rerun()
            
            with col_btn2:
                if st.button("🔄 새로고침", key="refresh_data"):
                    st.rerun()
            
            # 필터링 로직 적용
            filtered_df = df.copy()
            
            # ID 필터
            if id_filter:
                filtered_df = filtered_df[filtered_df['ID'].astype(str).str.contains(id_filter, na=False)]
            
            # 날짜 필터
            if date_filter:
                filtered_df = filtered_df[filtered_df['날짜'].astype(str).str.contains(date_filter, na=False)]
            
            # 회사 필터
            if company_filter != "전체":
                filtered_df = filtered_df[filtered_df['회사'] == company_filter]
            
            # 내용 필터
            if content_filter:
                filtered_df = filtered_df[filtered_df['내용'].astype(str).str.contains(content_filter, na=False, case=False)]
            
            # 상태 필터
            if status_filter != "전체":
                filtered_df = filtered_df[filtered_df['상태'] == status_filter]
            
            # 우선순위 필터
            if priority_filter != "전체":
                filtered_df = filtered_df[filtered_df['우선순위'] == priority_filter]
            
            # 담당자 필터
            if assignee_filter != "전체":
                filtered_df = filtered_df[filtered_df['담당자'] == assignee_filter]
            
            # 연관ID 필터
            if related_id_filter:
                filtered_df = filtered_df[filtered_df['연관ID'].astype(str).str.contains(related_id_filter, na=False)]
            
            # 필터링 결과 표시
            if len(filtered_df) != len(df):
                st.success(f"🔍 필터 적용 결과: {len(filtered_df)}개 / {len(df)}개 VOC")
            
            # 필터링된 데이터로 테이블 표시
            display_df = filtered_df
    else:
        display_df = df
    
    # 엑셀 스타일의 필터링 가능한 테이블 (항상 data_editor 사용)
    if st.session_state.get('edit_mode', False):
        # 편집 모드: 편집 가능
        edited_df = st.data_editor(
            display_df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "날짜": st.column_config.TextColumn("날짜", width=66),
                "회사": st.column_config.TextColumn("회사", width=200),
                "내용": st.column_config.TextColumn("내용", width=560),
                "상태": st.column_config.SelectboxColumn("상태", width=60, options=["대기", "진행중", "완료", "보류"]),
                "우선순위": st.column_config.SelectboxColumn("우선순위", width=60, options=["낮음", "보통", "높음", "긴급"]),
                "담당자": st.column_config.SelectboxColumn("담당자", width=66, options=user_names),
                "연관ID": st.column_config.NumberColumn("연관ID", width=60),
            },
            hide_index=True,
            key="voc_data_editor"
        )
        
        # 편집된 데이터를 세션 상태에 저장
        st.session_state['voc_edited_data'] = edited_df.to_dict('records')
        
        # 편집된 데이터가 있으면 시각적 피드백 제공
        if not edited_df.equals(display_df):
            st.info("💡 편집된 내용이 있습니다. 상단의 저장 버튼을 클릭하여 변경사항을 저장하세요.")
    else:
        # 읽기 전용 모드: 필터링만 가능 (편집 불가)
        filtered_df = st.data_editor(
            display_df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "날짜": st.column_config.TextColumn("날짜", width=66, disabled=True),
                "회사": st.column_config.TextColumn("회사", width=200, disabled=True),
                "내용": st.column_config.TextColumn("내용", width=560, disabled=True),
                "상태": st.column_config.TextColumn("상태", width=60, disabled=True),
                "우선순위": st.column_config.TextColumn("우선순위", width=60, disabled=True),
                "담당자": st.column_config.TextColumn("담당자", width=66, disabled=True),
                "연관ID": st.column_config.NumberColumn("연관ID", width=60, disabled=True),
            },
            hide_index=True,
            key="voc_data_viewer",
            disabled=True  # 전체 테이블을 읽기 전용으로 설정
        )
    
    # 샘플 데이터 생성 및 VOC 추가 기능
    with st.expander("샘플 데이터 생성 및 VOC 추가"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 샘플 데이터 생성")
            if st.button("📊 연관 VOC 샘플 데이터 생성", type="primary"):
                # 샘플 데이터를 세션 상태에 추가
                if 'sample_voc_data' not in st.session_state:
                    st.session_state.sample_voc_data = []
                
                sample_data = [
                    {
                        "ID": len(st.session_state.sample_voc_data) + 1,
                        "날짜": "2024-01-15",
                        "회사": "테크코리아",
                        "내용": "제품 A에 대한 초기 문의 - 성능 개선 요청",
                        "상태": "진행중",
                        "우선순위": "높음",
                        "담당자": "김개발",
                        "연관ID": 0
                    },
                    {
                        "ID": len(st.session_state.sample_voc_data) + 2,
                        "날짜": "2024-01-16",
                        "회사": "테크코리아",
                        "내용": "제품 A 성능 개선 후속 문의 - 추가 요구사항",
                        "상태": "대기",
                        "우선순위": "보통",
                        "담당자": "김개발",
                        "연관ID": 1
                    },
                    {
                        "ID": len(st.session_state.sample_voc_data) + 3,
                        "날짜": "2024-01-17",
                        "회사": "테크코리아",
                        "내용": "제품 A 최종 검토 및 승인 요청",
                        "상태": "대기",
                        "우선순위": "긴급",
                        "담당자": "김개발",
                        "연관ID": 1
                    },
                    {
                        "ID": len(st.session_state.sample_voc_data) + 4,
                        "날짜": "2024-01-18",
                        "회사": "스마트솔루션",
                        "내용": "새로운 프로젝트 제안서 요청",
                        "상태": "진행중",
                        "우선순위": "높음",
                        "담당자": "이기획",
                        "연관ID": 0
                    },
                    {
                        "ID": len(st.session_state.sample_voc_data) + 5,
                        "날짜": "2024-01-19",
                        "회사": "스마트솔루션",
                        "내용": "프로젝트 제안서 검토 및 수정 요청",
                        "상태": "대기",
                        "우선순위": "보통",
                        "담당자": "이기획",
                        "연관ID": 4
                    }
                ]
                
                st.session_state.sample_voc_data.extend(sample_data)
                st.success(f"✅ {len(sample_data)}개의 연관 VOC 샘플 데이터가 생성되었습니다!")
                st.rerun()
            
            if st.button("🗑️ 샘플 데이터 초기화"):
                if 'sample_voc_data' in st.session_state:
                    del st.session_state.sample_voc_data
                st.success("✅ 샘플 데이터가 초기화되었습니다!")
                st.rerun()
        
        with col2:
            st.markdown("### ➕ 새 VOC 추가")
            with st.form("add_voc_form"):
                voc_date = st.date_input("날짜")
                voc_company = st.text_input("회사명")
                voc_priority = st.selectbox("우선순위", ["낮음", "보통", "높음", "긴급"])
                voc_status = st.selectbox("상태", ["대기", "진행중", "완료", "보류"])
                voc_related_id = st.number_input("연관 ID (0: 최초 문의)", min_value=0, value=0)
                
                voc_content = st.text_area("VOC 내용")
                voc_action = st.text_area("액션 아이템")
                
                if st.form_submit_button("VOC 추가"):
                    # 세션 상태에 VOC 추가
                    if 'sample_voc_data' not in st.session_state:
                        st.session_state.sample_voc_data = []
                    
                    new_voc = {
                        "ID": len(st.session_state.sample_voc_data) + 1,
                        "날짜": str(voc_date),
                        "회사": voc_company,
                        "내용": voc_content,
                        "상태": voc_status,
                        "우선순위": voc_priority,
                        "담당자": "사용자",
                        "연관ID": voc_related_id
                    }
                    
                    st.session_state.sample_voc_data.append(new_voc)
                    st.success("VOC가 추가되었습니다!")
                    st.rerun()

def _render_company_tab():
    """Company 탭 렌더링"""
    st.subheader("회사 목록")
    
    # 회사 데이터 가져오기 (API 호출)
    company_data = _get_company_data()
    
    import pandas as pd
    df = pd.DataFrame(company_data)
    
    # 편집 모드일 때 편집 가능한 테이블 표시
    if st.session_state.get('edit_mode', False):
        # 편집된 데이터를 세션 상태에 저장
        edited_df = st.data_editor(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "회사명": st.column_config.TextColumn("회사명", width=200),
                "도메인": st.column_config.TextColumn("도메인", width=150),
                "매출": st.column_config.TextColumn("매출", width=100),
                "직원수": st.column_config.NumberColumn("직원수", width=80),
                "국가": st.column_config.TextColumn("국가", width=80),
            },
            hide_index=True,
            key="company_data_editor"
        )
        
        # 편집된 데이터를 세션 상태에 저장 (다른 키 사용)
        st.session_state['company_edited_data'] = edited_df.to_dict('records')
        
        # 편집된 데이터가 있으면 시각적 피드백 제공
        if not edited_df.equals(df):
            st.info("💡 편집된 내용이 있습니다. 저장 버튼을 클릭하여 변경사항을 저장하세요.")
    else:
        st.dataframe(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42),
                "회사명": st.column_config.TextColumn("회사명", width=200),
                "도메인": st.column_config.TextColumn("도메인", width=150),
                "매출": st.column_config.TextColumn("매출", width=100),
                "직원수": st.column_config.NumberColumn("직원수", width=80),
                "국가": st.column_config.TextColumn("국가", width=80),
            },
            hide_index=True,
        )
    
    # 회사 추가 기능
    with st.expander("새 회사 추가"):
        with st.form("add_company_form"):
            col1, col2 = st.columns(2)
            with col1:
                company_name = st.text_input("회사명")
                company_domain = st.text_input("도메인")
            with col2:
                company_revenue = st.text_input("매출")
                company_employee = st.number_input("직원수", min_value=0)
            
            company_nation = st.text_input("국가")
            
            if st.form_submit_button("회사 추가"):
                st.success("회사가 추가되었습니다! (실제 DB 연동 시 저장됩니다)")

def _render_contact_tab():
    """Contact 탭 렌더링"""
    st.subheader("연락처 목록")
    
    # 연락처 데이터 가져오기 (API 호출)
    contact_data = _get_contact_data()
    
    import pandas as pd
    df = pd.DataFrame(contact_data)
    
    # 편집 모드일 때 편집 가능한 테이블 표시
    if st.session_state.get('edit_mode', False):
        # 편집된 데이터를 세션 상태에 저장
        edited_df = st.data_editor(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "이름": st.column_config.TextColumn("이름", width=100),
                "직책": st.column_config.TextColumn("직책", width=100),
                "이메일": st.column_config.TextColumn("이메일", width=200),
                "전화": st.column_config.TextColumn("전화", width=120),
                "회사": st.column_config.TextColumn("회사", width=150),
                "메모": st.column_config.TextColumn("메모", width=200),
            },
            hide_index=True,
            key="contact_data_editor"
        )
        
        # 편집된 데이터를 세션 상태에 저장 (다른 키 사용)
        st.session_state['contact_edited_data'] = edited_df.to_dict('records')
        
        # 편집된 데이터가 있으면 시각적 피드백 제공
        if not edited_df.equals(df):
            st.info("💡 편집된 내용이 있습니다. 저장 버튼을 클릭하여 변경사항을 저장하세요.")
    else:
        st.dataframe(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42),
                "이름": st.column_config.TextColumn("이름", width=100),
                "직책": st.column_config.TextColumn("직책", width=100),
                "이메일": st.column_config.TextColumn("이메일", width=200),
                "전화": st.column_config.TextColumn("전화", width=120),
                "회사": st.column_config.TextColumn("회사", width=150),
                "메모": st.column_config.TextColumn("메모", width=200),
            },
            hide_index=True,
        )
    
    # 연락처 추가 기능
    with st.expander("새 연락처 추가"):
        with st.form("add_contact_form"):
            col1, col2 = st.columns(2)
            with col1:
                contact_name = st.text_input("이름")
                contact_title = st.text_input("직책")
            with col2:
                contact_email = st.text_input("이메일")
                contact_phone = st.text_input("전화번호")
            
            contact_company = st.selectbox("회사", ["ABC Corp", "XYZ Ltd", "DEF Inc"])
            contact_note = st.text_area("메모")
            
            if st.form_submit_button("연락처 추가"):
                st.success("연락처가 추가되었습니다! (실제 DB 연동 시 저장됩니다)")

def _render_project_tab():
    """Project 탭 렌더링"""
    st.subheader("프로젝트 목록")
    
    # 프로젝트 데이터 가져오기 (API 호출)
    project_data = _get_project_data()
    
    import pandas as pd
    df = pd.DataFrame(project_data)
    
    # 편집 모드일 때 편집 가능한 테이블 표시
    if st.session_state.get('edit_mode', False):
        # 편집된 데이터를 세션 상태에 저장
        edited_df = st.data_editor(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "프로젝트명": st.column_config.TextColumn("프로젝트명", width=200),
                "분야": st.column_config.TextColumn("분야", width=100),
                "대상앱": st.column_config.TextColumn("대상앱", width=100),
                "AI모델": st.column_config.TextColumn("AI모델", width=120),
                "성능": st.column_config.TextColumn("성능", width=100),
                "폼팩터": st.column_config.TextColumn("폼팩터", width=100),
                "메모리": st.column_config.TextColumn("메모리", width=100),
                "회사": st.column_config.TextColumn("회사", width=150),
                "상태": st.column_config.SelectboxColumn("상태", width=80, options=["대기", "진행중", "완료", "보류"]),
            },
            hide_index=True,
            key="project_data_editor"
        )
        
        # 편집된 데이터를 세션 상태에 저장 (다른 키 사용)
        st.session_state['project_edited_data'] = edited_df.to_dict('records')
        
        # 편집된 데이터가 있으면 시각적 피드백 제공
        if not edited_df.equals(df):
            st.info("💡 편집된 내용이 있습니다. 저장 버튼을 클릭하여 변경사항을 저장하세요.")
    else:
        st.dataframe(
            df,
            width="stretch",
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42),
                "프로젝트명": st.column_config.TextColumn("프로젝트명", width=200),
                "분야": st.column_config.TextColumn("분야", width=100),
                "대상앱": st.column_config.TextColumn("대상앱", width=100),
                "AI모델": st.column_config.TextColumn("AI모델", width=120),
                "성능": st.column_config.TextColumn("성능", width=100),
                "폼팩터": st.column_config.TextColumn("폼팩터", width=100),
                "메모리": st.column_config.TextColumn("메모리", width=100),
                "회사": st.column_config.TextColumn("회사", width=150),
                "상태": st.column_config.TextColumn("상태", width=80),
            },
            hide_index=True,
        )
    
    # 프로젝트 추가 기능
    with st.expander("새 프로젝트 추가"):
        with st.form("add_project_form"):
            col1, col2 = st.columns(2)
            with col1:
                project_name = st.text_input("프로젝트명")
                project_field = st.text_input("분야")
            with col2:
                project_app = st.text_input("대상앱")
                project_model = st.text_input("AI모델")
            
            project_company = st.selectbox("회사", ["ABC Corp", "XYZ Ltd", "DEF Inc"])
            project_perf = st.text_input("성능")
            project_form_factor = st.text_input("폼팩터")
            project_memory = st.text_input("메모리")
            project_requirements = st.text_area("요구사항")
            
            if st.form_submit_button("프로젝트 추가"):
                st.success("프로젝트가 추가되었습니다! (실제 DB 연동 시 저장됩니다)")

def _setup_dummy_users():
    """더미 사용자 데이터 설정"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/admin/setup-dummy-users",
            headers={"Authorization": f"Bearer {st.session_state.access_token}"}
        )
        if response.status_code == 200:
            result = response.json()
            return result.get('created_users', [])
        else:
            return []
    except Exception as e:
        return []

def _get_users_list():
    """사용자 목록 가져오기"""
    try:
        response = requests.get(
            f"{API_BASE_URL}/users/",
            headers={"Authorization": f"Bearer {st.session_state.access_token}"}
        )
        if response.status_code == 200:
            return response.json()
        return []
    except Exception:
        return []

def _get_user_id_by_name(name):
    """사용자 이름으로 ID 찾기"""
    try:
        users = _get_users_list()
        for user in users:
            if user.get('name') == name:
                return user.get('id')
        return 1  # 기본값
    except Exception:
        return 1  # 기본값

def _convert_frontend_to_api_data(data_type, data):
    """프론트엔드 데이터를 API 형식으로 변환"""
    converted_data = []
    
    for item in data:
        if data_type == 'voc':
            # 담당자 이름으로 사용자 ID 찾기
            assignee_name = item.get('담당자', '')
            assignee_id = _get_user_id_by_name(assignee_name) if assignee_name else 1
            
            converted_item = {
                "id": item.get('ID'),
                "date": item.get('날짜'),
                "content": item.get('내용'),
                "status": item.get('상태'),
                "priority": item.get('우선순위'),
                "assignee_user_id": assignee_id
            }
        elif data_type == 'company':
            converted_item = {
                "id": item.get('ID'),
                "name": item.get('회사명'),
                "domain": item.get('도메인'),
                "revenue": item.get('매출'),
                "employee": item.get('직원수'),
                "nation": item.get('국가')
            }
        elif data_type == 'contact':
            converted_item = {
                "id": item.get('ID'),
                "name": item.get('이름'),
                "title": item.get('직책'),
                "email": item.get('이메일'),
                "phone": item.get('전화'),
                "note": item.get('메모')
            }
        elif data_type == 'project':
            converted_item = {
                "id": item.get('ID'),
                "name": item.get('프로젝트명'),
                "field": item.get('분야'),
                "target_app": item.get('대상앱'),
                "ai_model": item.get('AI모델'),
                "perf": item.get('성능'),
                "form_factor": item.get('폼팩터'),
                "memory": item.get('메모리'),
                "status": item.get('상태')
            }
        
        # None 값 제거
        converted_item = {k: v for k, v in converted_item.items() if v is not None}
        converted_data.append(converted_item)
    
    return converted_data

def _save_all_changes():
    """모든 변경사항을 저장하는 함수"""
    try:
        # 편집된 데이터 가져오기
        edited_data = {}
        
        # VOC 편집 데이터 확인
        if 'voc_edited_data' in st.session_state:
            edited_data['voc'] = _convert_frontend_to_api_data('voc', st.session_state['voc_edited_data'])
        
        # Company 편집 데이터 확인
        if 'company_edited_data' in st.session_state:
            edited_data['company'] = _convert_frontend_to_api_data('company', st.session_state['company_edited_data'])
        
        # Contact 편집 데이터 확인
        if 'contact_edited_data' in st.session_state:
            edited_data['contact'] = _convert_frontend_to_api_data('contact', st.session_state['contact_edited_data'])
        
        # Project 편집 데이터 확인
        if 'project_edited_data' in st.session_state:
            edited_data['project'] = _convert_frontend_to_api_data('project', st.session_state['project_edited_data'])
        
        # 각 테이블별로 대량 업데이트 API 호출
        total_success = 0
        total_errors = 0
        all_errors = []
        
        # VOC 업데이트
        if 'voc' in edited_data and edited_data['voc']:
            try:
                response = requests.patch(
                    f"{API_BASE_URL}/voc/bulk-update",
                    headers={"Authorization": f"Bearer {st.session_state.access_token}"},
                    json={"vocs": edited_data['voc']}
                )
                if response.status_code == 200:
                    result = response.json()
                    total_success += result['success_count']
                    total_errors += result['error_count']
                    all_errors.extend(result['errors'])
                else:
                    st.error(f"VOC 업데이트 실패: {response.text}")
            except Exception as e:
                st.error(f"VOC 업데이트 중 오류 발생: {str(e)}")
        
        # Company 업데이트
        if 'company' in edited_data and edited_data['company']:
            try:
                response = requests.patch(
                    f"{API_BASE_URL}/companies/bulk-update",
                    headers={"Authorization": f"Bearer {st.session_state.access_token}"},
                    json={"companies": edited_data['company']}
                )
                if response.status_code == 200:
                    result = response.json()
                    total_success += result['success_count']
                    total_errors += result['error_count']
                    all_errors.extend(result['errors'])
                else:
                    st.error(f"Company 업데이트 실패: {response.text}")
            except Exception as e:
                st.error(f"Company 업데이트 중 오류 발생: {str(e)}")
        
        # Contact 업데이트
        if 'contact' in edited_data and edited_data['contact']:
            try:
                response = requests.patch(
                    f"{API_BASE_URL}/contacts/bulk-update",
                    headers={"Authorization": f"Bearer {st.session_state.access_token}"},
                    json={"contacts": edited_data['contact']}
                )
                if response.status_code == 200:
                    result = response.json()
                    total_success += result['success_count']
                    total_errors += result['error_count']
                    all_errors.extend(result['errors'])
                else:
                    st.error(f"Contact 업데이트 실패: {response.text}")
            except Exception as e:
                st.error(f"Contact 업데이트 중 오류 발생: {str(e)}")
        
        # Project 업데이트
        if 'project' in edited_data and edited_data['project']:
            try:
                response = requests.patch(
                    f"{API_BASE_URL}/projects/bulk-update",
                    headers={"Authorization": f"Bearer {st.session_state.access_token}"},
                    json={"projects": edited_data['project']}
                )
                if response.status_code == 200:
                    result = response.json()
                    total_success += result['success_count']
                    total_errors += result['error_count']
                    all_errors.extend(result['errors'])
                else:
                    st.error(f"Project 업데이트 실패: {response.text}")
            except Exception as e:
                st.error(f"Project 업데이트 중 오류 발생: {str(e)}")
        
        # 결과 표시
        if total_success > 0:
            st.success(f"✅ {total_success}개의 항목이 성공적으로 저장되었습니다!")
        
        if total_errors > 0:
            st.warning(f"⚠️ {total_errors}개의 항목에서 오류가 발생했습니다.")
            with st.expander("오류 상세 정보"):
                for error in all_errors:
                    st.error(error)
        
        # 편집 모드 종료 및 세션 상태 초기화
        st.session_state.edit_mode = False
        for key in ['voc_edited_data', 'company_edited_data', 'contact_edited_data', 'project_edited_data']:
            if key in st.session_state:
                del st.session_state[key]
        
        # 편집된 데이터 세션 상태에서 제거 (저장 완료 후)
        for key in ['voc_editor', 'company_editor', 'contact_editor', 'project_editor']:
            if key in st.session_state:
                del st.session_state[key]
        
    except Exception as e:
        st.error(f"저장 중 오류가 발생했습니다: {e}")


def _get_voc_data():
    """VOC 데이터 가져오기 (공용 사용을 위한 하이브리드 방식)"""
    try:
        # 환경변수에 따른 우선순위 결정
        if DATA_SOURCE_PRIORITY == "api_first":
            # 1. API 서버 우선 (공용 사용)
            data = api_get("/voc/")
            if data:
                voc_list = []
                for item in data:
                    voc_list.append({
                        "ID": item.get('id', 0),
                        "날짜": item.get('date', ''),
                        "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                        "내용": item.get('content', ''),
                        "상태": item.get('status', ''),
                        "우선순위": item.get('priority', ''),
                        "담당자": item.get('assignee', {}).get('name', '') if item.get('assignee') else '',
                        "연관ID": item.get('related_id', 0) if item.get('related_id') is not None else 0
                    })
                return voc_list
            
            # 2. API 실패 시 로컬 DB 백업
            connection = get_db_connection()
            if connection:
                try:
                    cursor = connection.cursor(dictionary=True)
                    # related_id 컬럼이 존재하는지 확인
                    cursor.execute("SHOW COLUMNS FROM vocs LIKE 'related_id'")
                    has_related_id = cursor.fetchone() is not None
                    
                    if has_related_id:
                        cursor.execute("""
                            SELECT v.id, v.date, v.content, v.status, v.priority, v.related_id,
                                   c.name as company_name, u.name as assignee_name
                            FROM vocs v
                            LEFT JOIN companies c ON v.company_id = c.id
                            LEFT JOIN users u ON v.assignee_user_id = u.id
                            ORDER BY v.date DESC
                            LIMIT 100
                        """)
                    else:
                        cursor.execute("""
                            SELECT v.id, v.date, v.content, v.status, v.priority, 0 as related_id,
                                   c.name as company_name, u.name as assignee_name
                            FROM vocs v
                            LEFT JOIN companies c ON v.company_id = c.id
                            LEFT JOIN users u ON v.assignee_user_id = u.id
                            ORDER BY v.date DESC
                            LIMIT 100
                        """)
                    
                    voc_list = []
                    for row in cursor.fetchall():
                        voc_list.append({
                            "ID": row['id'],
                            "날짜": row['date'],
                            "회사": row['company_name'] or '',
                            "내용": row['content'],
                            "상태": row['status'],
                            "우선순위": row['priority'],
                            "담당자": row['assignee_name'] or '',
                            "연관ID": row.get('related_id', 0) if row.get('related_id') is not None else 0
                        })
                    
                    if voc_list:
                        return voc_list
                        
                except Exception as e:
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🐛 DEBUG: 로컬 DB VOC 조회 실패: {e}")
                finally:
                    if connection and connection.is_connected():
                        cursor.close()
                        connection.close()
        
        else:
            # 1. 로컬 DB 우선 (개인 사용)
            connection = get_db_connection()
            if connection:
                try:
                    cursor = connection.cursor(dictionary=True)
                    # related_id 컬럼이 존재하는지 확인
                    cursor.execute("SHOW COLUMNS FROM vocs LIKE 'related_id'")
                    has_related_id = cursor.fetchone() is not None
                    
                    if has_related_id:
                        cursor.execute("""
                            SELECT v.id, v.date, v.content, v.status, v.priority, v.related_id,
                                   c.name as company_name, u.name as assignee_name
                            FROM vocs v
                            LEFT JOIN companies c ON v.company_id = c.id
                            LEFT JOIN users u ON v.assignee_user_id = u.id
                            ORDER BY v.date DESC
                            LIMIT 100
                        """)
                    else:
                        cursor.execute("""
                            SELECT v.id, v.date, v.content, v.status, v.priority, 0 as related_id,
                                   c.name as company_name, u.name as assignee_name
                            FROM vocs v
                            LEFT JOIN companies c ON v.company_id = c.id
                            LEFT JOIN users u ON v.assignee_user_id = u.id
                            ORDER BY v.date DESC
                            LIMIT 100
                        """)
                    
                    voc_list = []
                    for row in cursor.fetchall():
                        voc_list.append({
                            "ID": row['id'],
                            "날짜": row['date'],
                            "회사": row['company_name'] or '',
                            "내용": row['content'],
                            "상태": row['status'],
                            "우선순위": row['priority'],
                            "담당자": row['assignee_name'] or '',
                            "연관ID": row.get('related_id', 0) if row.get('related_id') is not None else 0
                        })
                    
                    if voc_list:
                        return voc_list
                        
                except Exception as e:
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🐛 DEBUG: 로컬 DB VOC 조회 실패: {e}")
                finally:
                    if connection and connection.is_connected():
                        cursor.close()
                        connection.close()
            
            # 2. 로컬 DB 실패 시 API 백업
            data = api_get("/voc/")
            if data:
                voc_list = []
                for item in data:
                    voc_list.append({
                        "ID": item.get('id', 0),
                        "날짜": item.get('date', ''),
                        "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                        "내용": item.get('content', ''),
                        "상태": item.get('status', ''),
                        "우선순위": item.get('priority', ''),
                        "담당자": item.get('assignee', {}).get('name', '') if item.get('assignee') else '',
                        "연관ID": item.get('related_id', 0) if item.get('related_id') is not None else 0
                    })
                return voc_list
        
        # 3. 모든 방법 실패 시 임시 데이터 반환
        return [
            {"ID": 1, "날짜": "2024-01-15", "회사": "ABC Corp", "내용": "시스템 오류 문의", "상태": "진행중", "우선순위": "높음", "담당자": "김철수"},
            {"ID": 2, "날짜": "2024-01-14", "회사": "XYZ Ltd", "내용": "기능 개선 요청", "상태": "완료", "우선순위": "보통", "담당자": "이영희"},
            {"ID": 3, "날짜": "2024-01-13", "회사": "DEF Inc", "내용": "성능 최적화 요청", "상태": "대기", "우선순위": "낮음", "담당자": "박민수"},
            {"ID": 4, "날짜": "2024-01-12", "회사": "GHI Co", "내용": "UI/UX 개선 요청", "상태": "진행중", "우선순위": "높음", "담당자": "최지영"},
            {"ID": 5, "날짜": "2024-01-11", "회사": "JKL Ltd", "내용": "보안 강화 요청", "상태": "완료", "우선순위": "긴급", "담당자": "정수현"},
            {"ID": 6, "날짜": "2024-01-10", "회사": "MNO Corp", "내용": "API 연동 문의", "상태": "진행중", "우선순위": "보통", "담당자": "김철수"},
            {"ID": 7, "날짜": "2024-01-09", "회사": "PQR Ltd", "내용": "데이터 마이그레이션 요청", "상태": "대기", "우선순위": "높음", "담당자": "이영희"},
        ]
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: VOC 데이터 조회 실패: {e}")
        return []

def _get_company_data():
    """회사 데이터 가져오기 (로컬 DB 우선)"""
    try:
        # 1. 로컬 DB에서 회사 데이터 조회
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT id, name, domain, revenue, employee, nation
                    FROM companies
                    ORDER BY name
                    LIMIT 100
                """)
                
                company_list = []
                for row in cursor.fetchall():
                    company_list.append({
                        "ID": row['id'],
                        "회사명": row['name'],
                        "도메인": row['domain'] or '',
                        "매출": row['revenue'] or '',
                        "직원수": row['employee'] or 0,
                        "국가": row['nation'] or ''
                    })
                
                if company_list:
                    return company_list
                    
            except Exception as e:
                if st.session_state.get('debug_mode', False):
                    st.write(f"🐛 DEBUG: 로컬 DB 회사 조회 실패: {e}")
            finally:
                if connection and connection.is_connected():
                    cursor.close()
                    connection.close()
        
        # 2. API에서 회사 데이터 가져오기 (백업용)
        data = api_get("/companies/")
        if data:
            company_list = []
            for item in data:
                company_list.append({
                    "ID": item.get('id', 0),
                    "회사명": item.get('name', ''),
                    "도메인": item.get('domain', ''),
                    "매출": item.get('revenue', ''),
                    "직원수": item.get('employee', 0),
                    "국가": item.get('nation', '')
                })
            return company_list
        
        # 3. 모든 방법 실패 시 임시 데이터 반환
        return [
            {"ID": 1, "회사명": "ABC Corp", "도메인": "abc.com", "매출": "100억", "직원수": 500, "국가": "한국"},
            {"ID": 2, "회사명": "XYZ Ltd", "도메인": "xyz.com", "매출": "50억", "직원수": 200, "국가": "미국"},
            {"ID": 3, "회사명": "DEF Inc", "도메인": "def.com", "매출": "200억", "직원수": 1000, "국가": "일본"},
            {"ID": 4, "회사명": "GHI Co", "도메인": "ghi.com", "매출": "80억", "직원수": 300, "국가": "한국"},
            {"ID": 5, "회사명": "JKL Ltd", "도메인": "jkl.com", "매출": "150억", "직원수": 800, "국가": "중국"},
            {"ID": 6, "회사명": "MNO Corp", "도메인": "mno.com", "매출": "120억", "직원수": 600, "국가": "미국"},
            {"ID": 7, "회사명": "PQR Ltd", "도메인": "pqr.com", "매출": "90억", "직원수": 400, "국가": "영국"},
        ]
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 회사 데이터 조회 실패: {e}")
        return []

def _get_contact_data():
    """연락처 데이터 가져오기 (로컬 DB 우선)"""
    try:
        # 1. 로컬 DB에서 연락처 데이터 조회
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT c.id, c.name, c.title, c.email, c.phone, c.note,
                           comp.name as company_name
                    FROM contacts c
                    LEFT JOIN companies comp ON c.company_id = comp.id
                    ORDER BY c.name
                    LIMIT 100
                """)
                
                contact_list = []
                for row in cursor.fetchall():
                    contact_list.append({
                        "ID": row['id'],
                        "이름": row['name'],
                        "직책": row['title'] or '',
                        "이메일": row['email'],
                        "전화": row['phone'] or '',
                        "회사": row['company_name'] or '',
                        "메모": row['note'] or ''
                    })
                
                if contact_list:
                    return contact_list
                    
            except Exception as e:
                if st.session_state.get('debug_mode', False):
                    st.write(f"🐛 DEBUG: 로컬 DB 연락처 조회 실패: {e}")
            finally:
                if connection and connection.is_connected():
                    cursor.close()
                    connection.close()
        
        # 2. API에서 연락처 데이터 가져오기 (백업용)
        data = api_get("/contacts/")
        if data:
            contact_list = []
            for item in data:
                contact_list.append({
                    "ID": item.get('id', 0),
                    "이름": item.get('name', ''),
                    "직책": item.get('title', ''),
                    "이메일": item.get('email', ''),
                    "전화": item.get('phone', ''),
                    "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                    "메모": item.get('note', '')
                })
            return contact_list
        
        # 3. 모든 방법 실패 시 임시 데이터 반환
        return [
            {"ID": 1, "이름": "John Smith", "직책": "CTO", "이메일": "john@abc.com", "전화": "+1-555-0123", "회사": "ABC Corp", "메모": "기술 담당자"},
            {"ID": 2, "이름": "Sarah Johnson", "직책": "PM", "이메일": "sarah@xyz.com", "전화": "+1-555-0456", "회사": "XYZ Ltd", "메모": "프로젝트 매니저"},
            {"ID": 3, "이름": "Takeshi Yamamoto", "직책": "CEO", "이메일": "takeshi@def.com", "전화": "+81-3-1234-5678", "회사": "DEF Inc", "메모": "최고 경영진"},
            {"ID": 4, "이름": "Li Wei", "직책": "개발팀장", "이메일": "liwei@ghi.com", "전화": "+86-10-1234-5678", "회사": "GHI Co", "메모": "개발 리더"},
            {"ID": 5, "이름": "Maria Garcia", "직책": "마케팅팀장", "이메일": "maria@jkl.com", "전화": "+34-91-123-4567", "회사": "JKL Ltd", "메모": "마케팅 담당자"},
            {"ID": 6, "이름": "David Brown", "직책": "개발팀장", "이메일": "david@mno.com", "전화": "+1-555-0789", "회사": "MNO Corp", "메모": "개발 리더"},
            {"ID": 7, "이름": "Emma Wilson", "직책": "PM", "이메일": "emma@pqr.com", "전화": "+44-20-1234-5678", "회사": "PQR Ltd", "메모": "프로젝트 매니저"},
        ]
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 연락처 데이터 조회 실패: {e}")
        return []

def _get_project_data():
    """프로젝트 데이터 가져오기 (로컬 DB 우선)"""
    try:
        # 1. 로컬 DB에서 프로젝트 데이터 조회
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT p.id, p.name, p.field, p.target_app, p.ai_model, p.perf, 
                           p.form_factor, p.memory, p.status,
                           c.name as company_name
                    FROM projects p
                    LEFT JOIN companies c ON p.company_id = c.id
                    ORDER BY p.name
                    LIMIT 100
                """)
                
                project_list = []
                for row in cursor.fetchall():
                    project_list.append({
                        "ID": row['id'],
                        "프로젝트명": row['name'],
                        "분야": row['field'] or '',
                        "대상앱": row['target_app'] or '',
                        "AI모델": row['ai_model'] or '',
                        "성능": row['perf'] or '',
                        "폼팩터": row['form_factor'] or '',
                        "메모리": row['memory'] or '',
                        "회사": row['company_name'] or '',
                        "상태": row['status'] or '진행중'
                    })
                
                if project_list:
                    return project_list
                    
            except Exception as e:
                if st.session_state.get('debug_mode', False):
                    st.write(f"🐛 DEBUG: 로컬 DB 프로젝트 조회 실패: {e}")
            finally:
                if connection and connection.is_connected():
                    cursor.close()
                    connection.close()
        
        # 2. API에서 프로젝트 데이터 가져오기 (백업용)
        data = api_get("/projects/")
        if data:
            project_list = []
            for item in data:
                project_list.append({
                    "ID": item.get('id', 0),
                    "프로젝트명": item.get('name', ''),
                    "분야": item.get('field', ''),
                    "대상앱": item.get('target_app', ''),
                    "AI모델": item.get('ai_model', ''),
                    "성능": item.get('perf', ''),
                    "폼팩터": item.get('form_factor', ''),
                    "메모리": item.get('memory', ''),
                    "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                    "상태": "진행중"  # 임시 상태
                })
            return project_list
        
        # 3. 모든 방법 실패 시 임시 데이터 반환
        return [
            {"ID": 1, "프로젝트명": "AI 챗봇 개발", "분야": "AI", "대상앱": "웹", "AI모델": "GPT-4", "성능": "고성능", "폼팩터": "서버", "메모리": "32GB", "회사": "ABC Corp", "상태": "진행중"},
            {"ID": 2, "프로젝트명": "데이터 분석", "분야": "Data", "대상앱": "모바일", "AI모델": "BERT", "성능": "중성능", "폼팩터": "모바일", "메모리": "8GB", "회사": "XYZ Ltd", "상태": "완료"},
            {"ID": 3, "프로젝트명": "이미지 인식", "분야": "CV", "대상앱": "데스크톱", "AI모델": "ResNet", "성능": "고성능", "폼팩터": "데스크톱", "메모리": "16GB", "회사": "DEF Inc", "상태": "대기"},
            {"ID": 4, "프로젝트명": "음성 인식", "분야": "NLP", "대상앱": "모바일", "AI모델": "Whisper", "성능": "고성능", "폼팩터": "모바일", "메모리": "6GB", "회사": "GHI Co", "상태": "진행중"},
            {"ID": 5, "프로젝트명": "추천 시스템", "분야": "ML", "대상앱": "웹", "AI모델": "Transformer", "성능": "중성능", "폼팩터": "클라우드", "메모리": "64GB", "회사": "JKL Ltd", "상태": "완료"},
            {"ID": 6, "프로젝트명": "API 연동", "분야": "Integration", "대상앱": "웹", "AI모델": "Custom", "성능": "중성능", "폼팩터": "서버", "메모리": "16GB", "회사": "MNO Corp", "상태": "진행중"},
            {"ID": 7, "프로젝트명": "데이터 마이그레이션", "분야": "Data", "대상앱": "서버", "AI모델": "N/A", "성능": "고성능", "폼팩터": "서버", "메모리": "128GB", "회사": "PQR Ltd", "상태": "대기"},
        ]
        
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"🐛 DEBUG: 프로젝트 데이터 조회 실패: {e}")
        return []

def _render_settings_modal_content():
    """설정 모달 내부 UI 렌더링"""
    st.subheader("회원 정보")
    # 오른쪽 상단에 회원정보 수정 버튼
    header_col1, header_col2 = st.columns([3, 1])
    with header_col2:
        if st.button("회원정보 수정"):
            st.session_state["reauth_context"] = "edit_profile"
            st.session_state["show_reauth_modal"] = True

    st.divider()

    # 실제 사용자 정보 렌더링 (세션 기준)
    st.write(f"이름 {st.session_state.get('username', '-')}")
    st.write(f"부서 {st.session_state.get('profile_department', '전략팀')}")
    st.write(f"이메일 {st.session_state.get('user_email', 'unknown@mail.com')}")

    st.write("")

    # 디버그 모드 토글 (모든 사용자)
    st.subheader("개발자 옵션")
    debug_mode = st.session_state.get('debug_mode', False)

    col_debug1, col_debug2 = st.columns([3, 1])
    with col_debug1:
        st.write("디버그 모드 (세션 상태 및 쿠키 정보 표시)")
    with col_debug2:
        if st.button("🟢 켜기" if not debug_mode else "🔴 끄기", key="toggle_debug"):
            st.session_state['debug_mode'] = not debug_mode
            st.rerun()

    st.divider()

    # 관리자 기능들
    if st.session_state.get('auth_level', 0) >= 4:
        st.subheader("관리자 기능")

        # 더미 사용자 설정 버튼
        if st.button("🎭 더미 사용자 설정", help="한국 이름의 더미 사용자 데이터를 생성합니다"):
            try:
                created_users = _setup_dummy_users()
                if created_users:
                    st.success(f"✅ {len(created_users)}명의 더미 사용자가 생성되었습니다!")
                    for user in created_users:
                        st.write(f"- {user['name']} ({user['email']}) - 레벨 {user['auth_level']}")
                else:
                    st.info("더미 사용자들이 이미 존재하거나 생성에 실패했습니다.")
            except Exception as e:
                st.error(f"더미 사용자 생성 중 오류: {e}")

        st.divider()
    
    btn_col1, btn_col2 = st.columns([1, 1])
    with btn_col1:
        # LV3 이상만 노출
        if st.session_state.get('auth_level', 0) >= 3:
            if st.button("회원관리"):
                st.session_state["reauth_context"] = "manage_users"
                st.session_state["show_reauth_modal"] = True
    with btn_col2:
        if st.button("닫기"):
            st.session_state["show_settings_modal"] = False

    # 하위 모달 렌더링
    _render_reauth_modal()
    _render_edit_profile_modal()
    _render_user_management_modal()

def _render_reauth_modal():
    """민감 작업 전 재인증 모달"""
    if not st.session_state.get("show_reauth_modal", False):
        return
    title = "본인 확인"
    with _modal_ctx(title, key="reauth_modal"):
        st.write("보안을 위해 현재 비밀번호를 다시 입력해 주세요.")
        with st.form("reauth_form"):
            current_pw = st.text_input("현재 비밀번호", type="password")
            col_a, col_b = st.columns([1,1])
            submitted = col_a.form_submit_button("확인")
            cancel = col_b.form_submit_button("취소")
        if submitted:
            # 파일 기반 사용자 인증
            user_email = st.session_state.get("user_email")
            temp_users = get_temp_users()
            user = temp_users.get(user_email)
            if user and verify_password(current_pw, user.get("password_hash", "")):
                ctx = st.session_state.get("reauth_context")
                st.session_state["show_reauth_modal"] = False
                st.session_state["show_settings_modal"] = True
                if ctx == "edit_profile":
                    st.session_state["show_edit_profile_modal"] = True
                elif ctx == "manage_users":
                    st.session_state["show_user_mgmt_modal"] = True
                st.rerun()
            else:
                st.error("비밀번호가 올바르지 않습니다.")
        if cancel:
            st.session_state["show_reauth_modal"] = False
            st.session_state.pop("reauth_context", None)
            st.session_state["show_settings_modal"] = True
            st.rerun()

def _render_edit_profile_modal():
    """회원정보 수정 모달"""
    if not st.session_state.get("show_edit_profile_modal", False):
        return
    with _modal_ctx("회원정보 수정", key="edit_profile_modal"):
        temp_users = get_temp_users()
        email = st.session_state.get("user_email", "")
        username = st.session_state.get("username", "")
        # 임시로 부서는 세션에 없으므로 로컬 상태로 관리
        if "profile_department" not in st.session_state:
            st.session_state["profile_department"] = "전략팀"

        with st.form("edit_profile_form"):
            name_val = st.text_input("이름", value=username)
            dept_val = st.text_input("부서", value=st.session_state["profile_department"]) 
            new_pw = st.text_input("새 비밀번호", type="password")
            new_pw2 = st.text_input("비밀번호 확인", type="password")
            col_a, col_b = st.columns([1,1])
            apply_clicked = col_a.form_submit_button("적용")
            cancel_clicked = col_b.form_submit_button("취소")

        if apply_clicked:
            # 이름/부서 업데이트
            st.session_state["username"] = name_val
            st.session_state["profile_department"] = dept_val
            # 파일 저장 (이름만 반영)
            if email in temp_users:
                temp_users[email]["username"] = name_val
                temp_users[email]["department"] = dept_val
                if new_pw or new_pw2:
                    if len(new_pw) < 6:
                        st.error("비밀번호는 6자리 이상이어야 합니다.")
                        st.stop()
                    if new_pw != new_pw2:
                        st.error("비밀번호가 일치하지 않습니다.")
                        st.stop()
                    temp_users[email]["password_hash"] = get_password_hash(new_pw)
                save_users_to_file(temp_users)
                # 세션 캐시 동기화
                st.session_state["temp_users"] = temp_users
            st.success("프로필이 업데이트되었습니다.")
            st.session_state["show_edit_profile_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()
        if cancel_clicked:
            st.session_state["show_edit_profile_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()

def _render_user_management_modal():
    """회원관리 모달 (LV3+)"""
    if not st.session_state.get("show_user_mgmt_modal", False):
        return
    with _modal_ctx("회원관리", key="user_mgmt_modal"):
        current_level = st.session_state.get("auth_level", 0)
        current_user_email = st.session_state.get("user_email")

        # 백엔드 API에서 사용자 목록 가져오기
        try:
            api_users = _get_users_list()
            if api_users:
                st.subheader("백엔드 사용자 목록")
                st.markdown("---")
                
                # 승인 대기 사용자 (레벨 0)
                pending_users = [user for user in api_users if user.get('auth_level') == 0 and user.get('is_active', True)]
                if pending_users:
                    st.write("**승인 대기 중인 사용자:**")
                    for user in pending_users:
                        c1, c2, c3, c4 = st.columns([2,2,1,1])
                        c1.write(f"{user.get('name', '-')} ({user.get('email', '-')})")
                        c2.write(f"레벨 {user.get('auth_level', 0)}")
                        if c3.button("승인", key=f"approve_api_{user.get('id')}"):
                            st.info("승인 기능은 백엔드 API를 통해 구현 필요")
                        if c4.button("거부", key=f"reject_api_{user.get('id')}"):
                            st.info("거부 기능은 백엔드 API를 통해 구현 필요")
                else:
                    st.write("승인 대기 중인 사용자가 없습니다.")
                
                st.markdown("---")
                
                # 활성 사용자 목록 (레벨 1 이상)
                active_users = [
                    user for user in api_users 
                    if user.get('auth_level', 0) > 0 and user.get('is_active', True) and user.get('email') != current_user_email
                ]
                
                if active_users:
                    st.write("**활성 사용자 목록:**")
                    for user in active_users:
                        c1, c2, c3 = st.columns([2,2,1])
                        c1.write(f"{user.get('name', '-')} ({user.get('email', '-')})")
                        c2.write(f"레벨 {user.get('auth_level', 0)}")
                        if c3.button("권한수정", key=f"role_api_{user.get('id')}"):
                            st.info("권한 수정 기능은 백엔드 API를 통해 구현 필요")
                else:
                    st.write("표시할 활성 사용자가 없습니다.")
                    
            else:
                st.warning("백엔드 API에서 사용자 목록을 가져올 수 없습니다.")
                
        except Exception as e:
            st.error(f"사용자 목록 조회 중 오류: {e}")
            
        # 기존 파일 기반 사용자 관리도 유지 (하위 호환성)
        st.markdown("---")
        st.subheader("파일 기반 사용자 관리 (기존)")
        temp_users = get_temp_users()
        
        # 승인 대기: auth_level == 0 and is_active == True
        pending = [(email, data) for email, data in temp_users.items() if data.get("auth_level", 0) == 0 and data.get("is_active", True)]
        if not pending:
            st.write("승인 대기 중인 사용자가 없습니다.")
        else:
            for email, data in pending:
                c1, c2, c3, c4 = st.columns([2,2,1,1])
                c1.write(f"{data.get('username','-')} ({email})")
                c2.write("p.w 제외")
                if c3.button("승인", key=f"approve_{email}"):
                    # 레벨 선택 팝업: 현재 사용자 레벨까지 선택 가능
                    st.session_state["approve_target_email"] = email
                    st.session_state["show_approve_modal"] = True
                    st.rerun()
                if c4.button("거부", key=f"reject_{email}"):
                    # 거부 처리: is_active를 False로 설정
                    temp_users = get_temp_users()
                    if email in temp_users:
                        temp_users[email]["is_active"] = False
                        save_users_to_file(temp_users)
                        st.session_state["temp_users"] = temp_users
                        st.success(f"{data.get('username','-')}님의 가입 신청을 거부했습니다.")
                        st.rerun()

        st.subheader("직원 리스트 (파일 기반)")
        st.markdown("---")
        # 자신 레벨 이하만 표시 (p.w 제외 표기) - 본인 제외, 활성 사용자만
        employees = [
            (email, data) for email, data in temp_users.items()
            if data.get("auth_level", 0) <= current_level and data.get("auth_level", 0) > 0 and email != current_user_email and data.get("is_active", True)
        ]
        if not employees:
            st.write("표시할 직원이 없습니다.")
        else:
            for email, data in employees:
                c1, c2, c3 = st.columns([2,3,1])
                c1.write(f"{data.get('username','-')} ({email})")
                c2.write("p.w 제외")
                if c3.button("권한수정", key=f"role_{email}"):
                    st.session_state["edit_role_target"] = email
                    st.session_state["show_role_edit_inline"] = True
            # 권한 수정 인라인 폼
            if st.session_state.get("show_role_edit_inline") and st.session_state.get("edit_role_target"):
                target_email = st.session_state["edit_role_target"]
                levels = [0,1,2,3,4,5]
                new_level = st.selectbox("권한 레벨 선택", levels, index=levels.index(temp_users[target_email]["auth_level"]))
                colx, coly = st.columns([1,1])
                if colx.button("적용", key="apply_role"):
                    # 자신보다 높은 레벨은 불가
                    if new_level > current_level:
                        st.error("자신보다 높은 레벨로 설정할 수 없습니다.")
                    else:
                        temp_users[target_email]["auth_level"] = new_level
                        save_users_to_file(temp_users)
                        # 세션 캐시 및 본인 변경 시 세션 레벨 반영
                        st.session_state["temp_users"] = temp_users
                        if target_email == st.session_state.get("user_email"):
                            st.session_state["auth_level"] = new_level
                        st.success("권한이 변경되었습니다.")
                        st.session_state.pop("show_role_edit_inline", None)
                        st.session_state.pop("edit_role_target", None)
                        st.session_state["show_settings_modal"] = True
                        st.rerun()
                if coly.button("취소", key="cancel_role"):
                    st.session_state.pop("show_role_edit_inline", None)
                    st.session_state.pop("edit_role_target", None)
                    st.session_state["show_settings_modal"] = True
                    st.rerun()

        st.write("")
        col_ok, col_cancel, col_deleted, col_rejected = st.columns([1,1,1,1])
        if col_ok.button("적용"):
            st.session_state["show_user_mgmt_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()
        if col_cancel.button("취소"):
            st.session_state["show_user_mgmt_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()
        if col_deleted.button("삭제회원"):
            st.session_state["show_deleted_users_modal"] = True
            st.rerun()
        if col_rejected.button("거부회원"):
            st.session_state["show_rejected_users_modal"] = True
            st.rerun()

    # 승인 레벨 선택 모달 (회원관리 내부 플로우)
    if st.session_state.get("show_approve_modal", False) and st.session_state.get("approve_target_email"):
        target_email = st.session_state["approve_target_email"]
        with _modal_ctx("승인 레벨 선택", key="approve_level_modal"):
            current_level = st.session_state.get("auth_level", 1)
            levels = list(range(1, current_level + 1))
            st.write("승인할 권한 레벨을 선택해 주세요.")
            new_level = st.selectbox("권한 레벨", levels, index=0)
            ca, cb = st.columns([1,1])
            if ca.button("확인", key="approve_apply"):
                temp_users = get_temp_users()
                if target_email in temp_users:
                    temp_users[target_email]["auth_level"] = new_level
                    save_users_to_file(temp_users)
                st.session_state["show_approve_modal"] = False
                st.session_state.pop("approve_target_email", None)
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.rerun()
            if cb.button("취소", key="approve_cancel"):
                st.session_state["show_approve_modal"] = False
                st.session_state.pop("approve_target_email", None)
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.rerun()

    # 삭제회원 모달 (1레벨 이상 비활성화 사용자)
    if st.session_state.get("show_deleted_users_modal", False):
        with _modal_ctx("삭제회원 관리", key="deleted_users_modal"):
            temp_users = get_temp_users()
            current_level = st.session_state.get("auth_level", 0)
            
            # 1레벨 이상이면서 비활성화된 사용자들
            deleted_users = [
                (email, data) for email, data in temp_users.items()
                if data.get("auth_level", 0) >= 1 and not data.get("is_active", True) and data.get("auth_level", 0) <= current_level
            ]
            
            if not deleted_users:
                st.write("삭제된 직원이 없습니다.")
            else:
                st.write(f"**삭제된 직원 목록 ({len(deleted_users)}명)**")
                st.markdown("---")
                for email, data in deleted_users:
                    col1, col2, col3 = st.columns([3, 1, 1])
                    with col1:
                        st.write(f"{data.get('username','-')} ({email}) - Level {data.get('auth_level', 0)}")
                    with col2:
                        if st.button("복구", key=f"restore_{email}"):
                            temp_users = get_temp_users()
                            if email in temp_users:
                                temp_users[email]["is_active"] = True
                                save_users_to_file(temp_users)
                                st.session_state["temp_users"] = temp_users
                                st.success(f"{data.get('username','-')}님의 계정이 복구되었습니다.")
                                st.rerun()
                    with col3:
                        if st.button("영구삭제", key=f"permanent_delete_{email}"):
                            temp_users = get_temp_users()
                            if email in temp_users:
                                del temp_users[email]
                                save_users_to_file(temp_users)
                                st.session_state["temp_users"] = temp_users
                                st.success(f"{data.get('username','-')}님의 계정이 영구삭제되었습니다.")
                                st.rerun()
            
            st.write("")
            if st.button("닫기", key="close_deleted_modal"):
                st.session_state["show_deleted_users_modal"] = False
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.rerun()

    # 거부회원 모달 (0레벨 비활성화 사용자)
    if st.session_state.get("show_rejected_users_modal", False):
        with _modal_ctx("거부회원 관리", key="rejected_users_modal"):
            temp_users = get_temp_users()
            
            # 0레벨이면서 비활성화된 사용자들
            rejected_users = [
                (email, data) for email, data in temp_users.items()
                if data.get("auth_level", 0) == 0 and not data.get("is_active", True)
            ]
            
            if not rejected_users:
                st.write("거부된 가입 신청이 없습니다.")
            else:
                st.write(f"**거부된 가입 신청 목록 ({len(rejected_users)}명)**")
                st.markdown("---")
                for email, data in rejected_users:
                    col1, col2, col3 = st.columns([3, 1, 1])
                    with col1:
                        st.write(f"{data.get('username','-')} ({email}) - 거부됨")
                    with col2:
                        if st.button("재승인", key=f"reapprove_{email}"):
                            temp_users = get_temp_users()
                            if email in temp_users:
                                temp_users[email]["is_active"] = True
                                save_users_to_file(temp_users)
                                st.session_state["temp_users"] = temp_users
                                st.success(f"{data.get('username','-')}님의 가입 신청이 재승인되었습니다.")
                                st.rerun()
                    with col3:
                        if st.button("영구삭제", key=f"permanent_reject_{email}"):
                            temp_users = get_temp_users()
                            if email in temp_users:
                                del temp_users[email]
                                save_users_to_file(temp_users)
                                st.session_state["temp_users"] = temp_users
                                st.success(f"{data.get('username','-')}님의 가입 신청이 영구삭제되었습니다.")
                                st.rerun()
            
            st.write("")
            if st.button("닫기", key="close_rejected_modal"):
                st.session_state["show_rejected_users_modal"] = False
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.rerun()

def main():
    """메인 함수"""
    st.set_page_config(
        page_title="VOC Management System",
        page_icon="🏢",
        layout="wide"
    )
    
    # 쿠키 매니저 초기화 대기
    if not cookies.ready():
        st.info("🔄 쿠키 매니저 초기화 중...")
        st.stop()
    
    # 세션 상태 초기화
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'password_reset_needed' not in st.session_state:
        st.session_state.password_reset_needed = False
    
    # 세션 복원 로직 개선 - 한 번만 실행 (성능 최적화)
    if not st.session_state.logged_in and 'session_restore_attempted' not in st.session_state:
        st.session_state['session_restore_attempted'] = True

        # 1. 파일 기반 세션 복원 먼저 시도 (가장 안정적)
        if initialize_session_from_localStorage():
            st.rerun()
            return

        # 2. 쿠키 기반 세션 복원 시도 (백업용)
        if initialize_session_from_cookie():
            st.rerun()
            return

    # 로그인된 상태에서 세션 유효성 검사 (경량화)
    if st.session_state.logged_in:
        if not check_session_validity():
            # 세션이 유효하지 않으면 로그아웃 처리
            clear_session_state()
            st.session_state['session_restore_attempted'] = False  # 재시도 가능하도록
            st.rerun()
            return
    
    # 페이지 라우팅
    if st.session_state.get('password_reset_needed', False):
        password_reset_page()
    elif st.session_state.get('logged_in', False):
        voc_table_page()
    else:
        login_page()

# =============================================================================
# 데이터 저장 함수들
# =============================================================================

def save_voc_changes(edited_df, original_df):
    """VOC 변경사항 저장"""
    try:
        # 변경된 행 찾기
        changes = []
        for idx, row in edited_df.iterrows():
            if idx < len(original_df):
                original_row = original_df.iloc[idx]
                # 변경된 필드 확인
                changed_fields = {}
                for col in edited_df.columns:
                    if col in original_df.columns and str(row[col]) != str(original_row[col]):
                        changed_fields[col] = {
                            'old': original_row[col],
                            'new': row[col]
                        }
                
                if changed_fields:
                    changes.append({
                        'id': row['ID'],
                        'changes': changed_fields
                    })
        
        if not changes:
            st.info("변경된 내용이 없습니다.")
            return
        
        # API를 통해 변경사항 저장
        success_count = 0
        for change in changes:
            try:
                # VOC 업데이트 API 호출
                voc_id = change['id']
                update_data = {}
                
                for field, values in change['changes'].items():
                    if field == '날짜':
                        update_data['date'] = str(values['new'])
                    elif field == '내용':
                        update_data['content'] = values['new']
                    elif field == '액션아이템':
                        update_data['action_item'] = values['new']
                    elif field == '마감일':
                        update_data['due_date'] = str(values['new']) if values['new'] else None
                    elif field == '상태':
                        update_data['status'] = values['new']
                    elif field == '우선순위':
                        update_data['priority'] = values['new']
                
                # API 호출
                response = update_voc_via_api(voc_id, update_data)
                if response:
                    success_count += 1
                    
            except Exception as e:
                st.error(f"VOC ID {change['id']} 저장 실패: {str(e)}")
        
        if success_count > 0:
            st.success(f"✅ {success_count}개의 VOC가 성공적으로 저장되었습니다.")
            st.rerun()
        else:
            st.error("저장에 실패했습니다.")
            
    except Exception as e:
        st.error(f"저장 중 오류가 발생했습니다: {str(e)}")

def save_company_changes(edited_df, original_df):
    """회사 변경사항 저장"""
    try:
        # 변경된 행 찾기
        changes = []
        for idx, row in edited_df.iterrows():
            if idx < len(original_df):
                original_row = original_df.iloc[idx]
                # 변경된 필드 확인
                changed_fields = {}
                for col in edited_df.columns:
                    if col in original_df.columns and str(row[col]) != str(original_row[col]):
                        changed_fields[col] = {
                            'old': original_row[col],
                            'new': row[col]
                        }
                
                if changed_fields:
                    changes.append({
                        'id': row['ID'],
                        'changes': changed_fields
                    })
        
        if not changes:
            st.info("변경된 내용이 없습니다.")
            return
        
        # API를 통해 변경사항 저장
        success_count = 0
        for change in changes:
            try:
                # 회사 업데이트 API 호출
                company_id = change['id']
                update_data = {}
                
                for field, values in change['changes'].items():
                    if field == '회사명':
                        update_data['name'] = values['new']
                    elif field == '도메인':
                        update_data['domain'] = values['new']
                    elif field == '매출':
                        update_data['revenue'] = values['new']
                    elif field == '직원수':
                        update_data['employee'] = values['new']
                    elif field == '국가':
                        update_data['nation'] = values['new']
                
                # API 호출
                response = update_company_via_api(company_id, update_data)
                if response:
                    success_count += 1
                    
            except Exception as e:
                st.error(f"회사 ID {change['id']} 저장 실패: {str(e)}")
        
        if success_count > 0:
            st.success(f"✅ {success_count}개의 회사가 성공적으로 저장되었습니다.")
            st.rerun()
        else:
            st.error("저장에 실패했습니다.")
            
    except Exception as e:
        st.error(f"저장 중 오류가 발생했습니다: {str(e)}")

def save_contact_changes(edited_df, original_df):
    """연락처 변경사항 저장"""
    try:
        # 변경된 행 찾기
        changes = []
        for idx, row in edited_df.iterrows():
            if idx < len(original_df):
                original_row = original_df.iloc[idx]
                # 변경된 필드 확인
                changed_fields = {}
                for col in edited_df.columns:
                    if col in original_df.columns and str(row[col]) != str(original_row[col]):
                        changed_fields[col] = {
                            'old': original_row[col],
                            'new': row[col]
                        }
                
                if changed_fields:
                    changes.append({
                        'id': row['ID'],
                        'changes': changed_fields
                    })
        
        if not changes:
            st.info("변경된 내용이 없습니다.")
            return
        
        # API를 통해 변경사항 저장
        success_count = 0
        for change in changes:
            try:
                # 연락처 업데이트 API 호출
                contact_id = change['id']
                update_data = {}
                
                for field, values in change['changes'].items():
                    if field == '이름':
                        update_data['name'] = values['new']
                    elif field == '직책':
                        update_data['title'] = values['new']
                    elif field == '이메일':
                        update_data['email'] = values['new']
                    elif field == '전화번호':
                        update_data['phone'] = values['new']
                    elif field == '메모':
                        update_data['note'] = values['new']
                
                # API 호출
                response = update_contact_via_api(contact_id, update_data)
                if response:
                    success_count += 1
                    
            except Exception as e:
                st.error(f"연락처 ID {change['id']} 저장 실패: {str(e)}")
        
        if success_count > 0:
            st.success(f"✅ {success_count}개의 연락처가 성공적으로 저장되었습니다.")
            st.rerun()
        else:
            st.error("저장에 실패했습니다.")
            
    except Exception as e:
        st.error(f"저장 중 오류가 발생했습니다: {str(e)}")

def save_project_changes(edited_df, original_df):
    """프로젝트 변경사항 저장"""
    try:
        # 변경된 행 찾기
        changes = []
        for idx, row in edited_df.iterrows():
            if idx < len(original_df):
                original_row = original_df.iloc[idx]
                # 변경된 필드 확인
                changed_fields = {}
                for col in edited_df.columns:
                    if col in original_df.columns and str(row[col]) != str(original_row[col]):
                        changed_fields[col] = {
                            'old': original_row[col],
                            'new': row[col]
                        }
                
                if changed_fields:
                    changes.append({
                        'id': row['ID'],
                        'changes': changed_fields
                    })
        
        if not changes:
            st.info("변경된 내용이 없습니다.")
            return
        
        # API를 통해 변경사항 저장
        success_count = 0
        for change in changes:
            try:
                # 프로젝트 업데이트 API 호출
                project_id = change['id']
                update_data = {}
                
                for field, values in change['changes'].items():
                    if field == '프로젝트명':
                        update_data['name'] = values['new']
                    elif field == '분야':
                        update_data['field'] = values['new']
                    elif field == '대상앱':
                        update_data['target_app'] = values['new']
                    elif field == 'AI모델':
                        update_data['ai_model'] = values['new']
                    elif field == '성능':
                        update_data['perf'] = values['new']
                    elif field == '전력':
                        update_data['power'] = values['new']
                    elif field == '폼팩터':
                        update_data['form_factor'] = values['new']
                    elif field == '메모리':
                        update_data['memory'] = values['new']
                    elif field == '가격':
                        update_data['price'] = values['new']
                    elif field == '요구사항':
                        update_data['requirements'] = values['new']
                    elif field == '경쟁사':
                        update_data['competitors'] = values['new']
                    elif field == '결과':
                        update_data['result'] = values['new']
                    elif field == '근본원인':
                        update_data['root_cause'] = values['new']
                
                # API 호출
                response = update_project_via_api(project_id, update_data)
                if response:
                    success_count += 1
                    
            except Exception as e:
                st.error(f"프로젝트 ID {change['id']} 저장 실패: {str(e)}")
        
        if success_count > 0:
            st.success(f"✅ {success_count}개의 프로젝트가 성공적으로 저장되었습니다.")
            st.rerun()
        else:
            st.error("저장에 실패했습니다.")
            
    except Exception as e:
        st.error(f"저장 중 오류가 발생했습니다: {str(e)}")

# =============================================================================
# API 호출 함수들
# =============================================================================

def update_voc_via_api(voc_id, update_data):
    """VOC 업데이트 API 호출"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return False
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.patch(
            f"{API_BASE_URL}/voc/{voc_id}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            st.error("권한이 없습니다. 이 VOC를 수정할 수 없습니다.")
            return False
        else:
            st.error(f"VOC 업데이트 실패: {response.text}")
            return False
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")
        return False

def update_company_via_api(company_id, update_data):
    """회사 업데이트 API 호출"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return False
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.patch(
            f"{API_BASE_URL}/companies/{company_id}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            st.error("권한이 없습니다. 이 회사를 수정할 수 없습니다.")
            return False
        else:
            st.error(f"회사 업데이트 실패: {response.text}")
            return False
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")
        return False

def update_contact_via_api(contact_id, update_data):
    """연락처 업데이트 API 호출"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return False
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.patch(
            f"{API_BASE_URL}/contacts/{contact_id}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            st.error("권한이 없습니다. 이 연락처를 수정할 수 없습니다.")
            return False
        else:
            st.error(f"연락처 업데이트 실패: {response.text}")
            return False
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")
        return False

def update_project_via_api(project_id, update_data):
    """프로젝트 업데이트 API 호출"""
    try:
        token = st.session_state.get('session_token')
        if not token:
            st.error("인증 토큰이 없습니다.")
            return False
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.patch(
            f"{API_BASE_URL}/projects/{project_id}",
            json=update_data,
            headers=headers
        )
        
        if response.status_code == 200:
            return True
        elif response.status_code == 403:
            st.error("권한이 없습니다. 이 프로젝트를 수정할 수 없습니다.")
            return False
        else:
            st.error(f"프로젝트 업데이트 실패: {response.text}")
            return False
            
    except Exception as e:
        st.error(f"API 호출 중 오류: {str(e)}")
        return False

if __name__ == "__main__":
    main()