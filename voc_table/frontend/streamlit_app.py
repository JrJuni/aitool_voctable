import streamlit as st
import streamlit.components.v1 as components
import requests
import hashlib
import time
import json
import os
import tempfile
from typing import Optional, Dict, Any

# 백엔드 API URL 설정
API_BASE_URL = os.getenv("API_BASE_URL", "http://172.16.5.75:8000")

# API 호출 헬퍼 함수들
def get_auth_headers():
    """인증 헤더 생성"""
    if 'session_token' in st.session_state:
        return {"Authorization": f"Bearer {st.session_state.session_token}"}
    return {}

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

def generate_session_token(email: str) -> str:
    """세션 토큰 생성"""
    timestamp = str(int(time.time()))
    raw_token = f"{email}_{timestamp}_voc_session"
    return hashlib.md5(raw_token.encode()).hexdigest()[:16]

def validate_session_token(token: str, email: str) -> bool:
    """세션 토큰 검증"""
    if not token or len(token) != 16:
        return False
    # 실제 운영환경에서는 더 강력한 검증이 필요합니다
    return True

def auto_login_from_url():
    """URL 파라미터에서 자동 로그인 시도"""
    query_params = st.experimental_get_query_params()
    
    if 'token' in query_params and 'email' in query_params:
        token = query_params['token']
        email = query_params['email']
        
        if validate_session_token(token, email):
            # 사용자 정보 다시 조회
            temp_users = get_temp_users()
            user = temp_users.get(email)
            if user and user['is_active'] and user['auth_level'] > 0:
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.session_state.username = user['username']
                st.session_state.auth_level = user['auth_level']
                st.session_state.profile_department = user.get('department', '전략팀')
                st.session_state.session_token = token
                return True
    return False

# 사용자 데이터 파일 경로를 모듈 디렉터리 기준으로 고정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DATA_FILE = os.path.join(BASE_DIR, "user_data.json")

def _default_users():
    return {
        "admin@mobilint.com": {
            "username": "admin",
            "password_hash": get_password_hash("0000"),
            "auth_level": 5,
            "is_active": True,
            "department": "HR"
        },
        "user@example.com": {
            "username": "user",
            "password_hash": get_password_hash("password123"),
            "auth_level": 1,
            "is_active": True,
            "department": "전략팀"
        },
        "manager@example.com": {
            "username": "manager",
            "password_hash": get_password_hash("0000"),
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
    return verify_password("0000", user["password_hash"]) and password == "0000"

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
    
    temp_users[email]["password_hash"] = get_password_hash("0000")
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
            elif new_password == "0000":
                st.error("보안을 위해 0000은 사용할 수 없습니다.")
            else:
                if update_user_password(st.session_state.user_email, new_password):
                    # 비밀번호 변경 후 자동 로그인 처리
                    temp_users = get_temp_users()
                    user = temp_users.get(st.session_state.user_email)
                    
                    st.session_state.logged_in = True
                    st.session_state.username = user["username"]
                    st.session_state.auth_level = user["auth_level"]
                    st.session_state.password_reset_needed = False
                    
                    # 세션 토큰 생성 및 URL 업데이트
                    token = generate_session_token(st.session_state.user_email)
                    st.session_state.session_token = token
                    st.query_params.update({"token": token, "email": st.session_state.user_email})
                    
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
                    # 비밀번호 재설정 필요 확인
                    if check_password_reset_needed(email, password):
                        st.session_state.user_email = email
                        st.session_state.password_reset_needed = True
                        st.rerun()
                        return
                    
                    user_info = authenticate_user(email, password)
                    if user_info and user_info["authenticated"]:
                        st.session_state.logged_in = True
                        st.session_state.user_email = email
                        st.session_state.username = user_info["username"]
                        st.session_state.auth_level = user_info["auth_level"]
                        
                        # 세션 토큰 생성 및 URL 업데이트
                        token = generate_session_token(email)
                        st.session_state.session_token = token
                        st.query_params.update({"token": token, "email": email})
                        
                        st.success("로그인 성공!")
                        st.rerun()
                    else:
                        st.error("잘못된 비밀번호입니다.")
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
                                        st.success("비밀번호가 0000으로 초기화되었습니다.")
                                        st.rerun()
                                    else:
                                        st.error("초기화에 실패했습니다.")
                    else:
                        st.warning("초기화 권한이 있는 사용자가 없습니다.")
                else:
                    st.error("이메일 또는 사용자명이 올바르지 않습니다.")
            else:
                st.error("이메일과 사용자명을 입력하세요.")

def voc_table_page():
    """VOC 테이블 페이지"""
    st.title("📊 VOC Management Dashboard")
    
    # 상단 사용자 정보 (우측 정렬, 버튼 간 간격 축소)
    top_left, top_settings, top_logout = st.columns([6.8, 1.0, 1.4])
    with top_left:
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
                # 세션 상태 초기화
                for key in ['logged_in', 'user_email', 'username', 'auth_level', 'session_token']:
                    if key in st.session_state:
                        del st.session_state[key]
                # URL 파라미터 제거
                st.query_params.clear()
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
    
    # 테이블 헤더 가운데 정렬을 위한 경량 CSS 주입
    st.markdown(
        """
        <style>
        /* st.dataframe 헤더 가운데 정렬 */
        div[data-testid="stDataFrame"] thead tr th div {
            display: flex; justify-content: center; align-items: center;
        }
        div[data-testid="stDataFrame"] thead tr th {
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
        
        /* 편집 모드 시각적 개선 */
        div[data-testid="stDataEditor"] {
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 10px;
            background-color: #fff5f5;
        }
        
        /* 편집 중인 셀 하이라이트 */
        div[data-testid="stDataEditor"] input:focus,
        div[data-testid="stDataEditor"] select:focus {
            border: 2px solid #4ecdc4 !important;
            box-shadow: 0 0 5px rgba(78, 205, 196, 0.5) !important;
        }
        
        /* 편집된 행 하이라이트 */
        div[data-testid="stDataEditor"] tr:hover {
            background-color: #f0f8ff !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    
    # VOC 데이터 가져오기 (API 호출)
    voc_data = _get_voc_data()
    
    # DataFrame으로 변환 후 컬럼 폭 조정
    import pandas as pd
    df = pd.DataFrame(voc_data)

    # 편집 모드일 때 편집 가능한 테이블 표시
    if st.session_state.get('edit_mode', False):
        # 사용자 목록 가져오기
        users = _get_users_list()
        user_names = [user.get('name', '') for user in users if user.get('name')]
        
        # 편집된 데이터를 세션 상태에 저장
        edited_df = st.data_editor(
            df,
            use_container_width=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "날짜": st.column_config.TextColumn("날짜", width=66),
                "회사": st.column_config.TextColumn("회사", width=200),
                "내용": st.column_config.TextColumn("내용", width=560),
                "상태": st.column_config.SelectboxColumn("상태", width=60, options=["대기", "진행중", "완료", "보류"]),
                "우선순위": st.column_config.SelectboxColumn("우선순위", width=60, options=["낮음", "보통", "높음", "긴급"]),
                "담당자": st.column_config.SelectboxColumn("담당자", width=66, options=user_names),
            },
            hide_index=True,
            key="voc_data_editor"
        )
        
        # 편집된 데이터를 세션 상태에 저장 (다른 키 사용)
        st.session_state['voc_edited_data'] = edited_df.to_dict('records')
        
        # 편집된 데이터가 있으면 시각적 피드백 제공
        if not edited_df.equals(df):
            st.info("💡 편집된 내용이 있습니다. 상단의 저장 버튼을 클릭하여 변경사항을 저장하세요.")
    else:
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42),
                "날짜": st.column_config.TextColumn("날짜", width=66),
                "회사": st.column_config.TextColumn("회사", width=200),
                "내용": st.column_config.TextColumn("내용", width=560),
                "상태": st.column_config.TextColumn("상태", width=60),
                "우선순위": st.column_config.TextColumn("우선순위", width=60),
                "담당자": st.column_config.TextColumn("담당자", width=66),
            },
            hide_index=True,
        )
    
    # VOC 추가 기능
    with st.expander("새 VOC 추가"):
        with st.form("add_voc_form"):
            col1, col2 = st.columns(2)
            with col1:
                voc_date = st.date_input("날짜")
                voc_company = st.text_input("회사명")
            with col2:
                voc_priority = st.selectbox("우선순위", ["낮음", "보통", "높음", "긴급"])
                voc_status = st.selectbox("상태", ["대기", "진행중", "완료", "보류"])
            
            voc_content = st.text_area("VOC 내용")
            voc_action = st.text_area("액션 아이템")
            
            if st.form_submit_button("VOC 추가"):
                st.success("VOC가 추가되었습니다! (실제 DB 연동 시 저장됩니다)")

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
            use_container_width=True,
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
            use_container_width=True,
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
            use_container_width=True,
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
            use_container_width=True,
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
            use_container_width=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42, disabled=True),
                "프로젝트명": st.column_config.TextColumn("프로젝트명", width=200),
                "분야": st.column_config.TextColumn("분야", width=100),
                "대상앱": st.column_config.TextColumn("대상앱", width=100),
                "AI모델": st.column_config.TextColumn("AI모델", width=120),
                "성능": st.column_config.TextColumn("성능", width=100),
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
            use_container_width=True,
            column_config={
                "ID": st.column_config.NumberColumn("ID", width=42),
                "프로젝트명": st.column_config.TextColumn("프로젝트명", width=200),
                "분야": st.column_config.TextColumn("분야", width=100),
                "대상앱": st.column_config.TextColumn("대상앱", width=100),
                "AI모델": st.column_config.TextColumn("AI모델", width=120),
                "성능": st.column_config.TextColumn("성능", width=100),
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
    """VOC 데이터 가져오기"""
    try:
        # API에서 VOC 데이터 가져오기
        data = api_get("/voc/")
        if data:
            # API 응답을 표시용 데이터로 변환
            voc_list = []
            for item in data:
                voc_list.append({
                    "ID": item.get('id', 0),
                    "날짜": item.get('date', ''),
                    "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                    "내용": item.get('content', ''),
                    "상태": item.get('status', ''),
                    "우선순위": item.get('priority', ''),
                    "담당자": item.get('assignee', {}).get('name', '') if item.get('assignee') else ''
                })
            return voc_list
        else:
            # API 호출 실패 시 임시 데이터 반환 (User 테이블의 실제 사용자들과 연결)
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
        # API 서버가 실행되지 않은 경우 조용히 처리
        return []

def _get_company_data():
    """회사 데이터 가져오기"""
    try:
        # API에서 회사 데이터 가져오기
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
        else:
            # API 호출 실패 시 임시 데이터 반환
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
        # API 서버가 실행되지 않은 경우 조용히 처리
        return []

def _get_contact_data():
    """연락처 데이터 가져오기"""
    try:
        # API에서 연락처 데이터 가져오기
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
        else:
            # API 호출 실패 시 임시 데이터 반환
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
        # API 서버가 실행되지 않은 경우 조용히 처리
        return []

def _get_project_data():
    """프로젝트 데이터 가져오기"""
    try:
        # API에서 프로젝트 데이터 가져오기
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
                    "회사": item.get('company', {}).get('name', '') if item.get('company') else '',
                    "상태": "진행중"  # 임시 상태
                })
            return project_list
        else:
            # API 호출 실패 시 임시 데이터 반환
            return [
                {"ID": 1, "프로젝트명": "AI 챗봇 개발", "분야": "AI", "대상앱": "웹", "AI모델": "GPT-4", "성능": "고성능", "회사": "ABC Corp", "상태": "진행중"},
                {"ID": 2, "프로젝트명": "데이터 분석", "분야": "Data", "대상앱": "모바일", "AI모델": "BERT", "성능": "중성능", "회사": "XYZ Ltd", "상태": "완료"},
                {"ID": 3, "프로젝트명": "이미지 인식", "분야": "CV", "대상앱": "데스크톱", "AI모델": "ResNet", "성능": "고성능", "회사": "DEF Inc", "상태": "대기"},
                {"ID": 4, "프로젝트명": "음성 인식", "분야": "NLP", "대상앱": "모바일", "AI모델": "Whisper", "성능": "고성능", "회사": "GHI Co", "상태": "진행중"},
                {"ID": 5, "프로젝트명": "추천 시스템", "분야": "ML", "대상앱": "웹", "AI모델": "Transformer", "성능": "중성능", "회사": "JKL Ltd", "상태": "완료"},
                {"ID": 6, "프로젝트명": "API 연동", "분야": "Integration", "대상앱": "웹", "AI모델": "Custom", "성능": "중성능", "회사": "MNO Corp", "상태": "진행중"},
                {"ID": 7, "프로젝트명": "데이터 마이그레이션", "분야": "Data", "대상앱": "서버", "AI모델": "N/A", "성능": "고성능", "회사": "PQR Ltd", "상태": "대기"},
            ]
    except Exception as e:
        # API 서버가 실행되지 않은 경우 조용히 처리
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
    
    # 세션 상태 초기화
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'password_reset_needed' not in st.session_state:
        st.session_state.password_reset_needed = False
    
    # 로그인되지 않은 상태에서 URL 파라미터로 자동 로그인 시도
    if not st.session_state.logged_in:
        auto_login_from_url()
    
    # 페이지 라우팅
    if st.session_state.get('password_reset_needed', False):
        password_reset_page()
    elif st.session_state.get('logged_in', False):
        voc_table_page()
    else:
        login_page()

if __name__ == "__main__":
    main()