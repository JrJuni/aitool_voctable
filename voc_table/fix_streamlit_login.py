#!/usr/bin/env python3
"""
Streamlit 로그인 문제 수정 스크립트
- st.query_params -> st.session_state로 변경
- 로그인 세션 유지 개선
"""

import re

def fix_streamlit_code():
    # Docker 컨테이너에서 파일 읽기
    import subprocess

    # 현재 streamlit_app.py 내용 가져오기
    result = subprocess.run(
        ["docker", "exec", "voc_frontend", "cat", "streamlit_app.py"],
        capture_output=True,
        text=True,
        cwd="voc_table"
    )

    if result.returncode != 0:
        print("Error reading streamlit_app.py from container")
        return False

    content = result.stdout

    # 1. st.query_params.update() -> 세션 상태로 변경
    content = re.sub(
        r'st\.query_params\.update\(.*?\)',
        '# query_params removed - using session state only',
        content
    )

    # 2. st.query_params.clear() -> 세션 상태만 사용
    content = re.sub(
        r'st\.query_params\.clear\(\)',
        '# query_params removed - using session state only',
        content
    )

    # 3. st.experimental_get_query_params() 사용 제거 및 세션 기반으로 변경
    old_auth_check = """# 로그인 상태 확인 (URL 파라미터 또는 세션 상태)
def check_login():
    query_params = st.experimental_get_query_params()

    if 'token' in query_params and 'email' in query_params:
        token = query_params['token']
        email = query_params['email']

        # 토큰 검증 및 세션 설정
        if verify_session_token(token, email):
            user_data = get_user_by_email(email)
            if user_data:
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.session_state.username = user_data.get("username", "Unknown")
                st.session_state.auth_level = user_data.get("auth_level", 0)
                st.session_state.session_token = token
                return True

    # 세션 상태 확인
    return st.session_state.get('logged_in', False)"""

    new_auth_check = """# 로그인 상태 확인 (세션 상태만 사용)
def check_login():
    # 세션 상태에서 로그인 확인
    if st.session_state.get('logged_in', False):
        # 토큰이 있으면 검증
        if 'session_token' in st.session_state and 'user_email' in st.session_state:
            token = st.session_state.session_token
            email = st.session_state.user_email

            # 토큰 검증
            if verify_session_token(token, email):
                return True
            else:
                # 토큰이 만료되었으면 로그아웃
                for key in ['logged_in', 'user_email', 'username', 'auth_level', 'session_token']:
                    if key in st.session_state:
                        del st.session_state[key]
                return False

    return False"""

    content = content.replace(old_auth_check, new_auth_check)

    # 4. 세션 토큰 생성 함수 개선 (더 긴 만료 시간)
    old_token_gen = """def generate_session_token(email):
    \"\"\"간단한 세션 토큰 생성\"\"\"
    return hashlib.sha256(f"{email}{time.time()}".encode()).hexdigest()"""

    new_token_gen = """def generate_session_token(email):
    \"\"\"세션 토큰 생성 (24시간 유효)\"\"\"
    import time
    import json
    import base64

    # 24시간 후 만료
    expire_time = time.time() + (24 * 60 * 60)
    token_data = {
        "email": email,
        "expire": expire_time
    }

    # Base64로 인코딩하여 토큰 생성
    token_json = json.dumps(token_data)
    token_b64 = base64.b64encode(token_json.encode()).decode()

    return token_b64"""

    content = content.replace(old_token_gen, new_token_gen)

    # 5. 토큰 검증 함수도 개선
    old_verify = """def verify_session_token(token, email):
    \"\"\"세션 토큰 검증\"\"\"
    # 간단한 검증 로직 (실제 구현에서는 더 복잡해야 함)
    return len(token) == 64"""

    new_verify = """def verify_session_token(token, email):
    \"\"\"세션 토큰 검증\"\"\"
    try:
        import json
        import base64

        # Base64 디코딩
        token_json = base64.b64decode(token.encode()).decode()
        token_data = json.loads(token_json)

        # 이메일 확인
        if token_data.get("email") != email:
            return False

        # 만료 시간 확인
        if time.time() > token_data.get("expire", 0):
            return False

        return True
    except:
        return False"""

    content = content.replace(old_verify, new_verify)

    # 6. 로그인 성공 후 query_params 업데이트 제거
    login_pattern = r'st\.query_params\.update\(\{"token": token, "email": email\}\)'
    content = re.sub(login_pattern, '# Token saved in session state only', content)

    # 7. 로그아웃 시 query_params.clear() 제거
    logout_pattern = r'st\.query_params\.clear\(\)'
    content = re.sub(logout_pattern, '# Query params not used', content)

    # 임시 파일에 저장
    with open("voc_table/frontend/streamlit_app_fixed.py", "w", encoding="utf-8") as f:
        f.write(content)

    print("Fixed streamlit_app.py saved as streamlit_app_fixed.py")
    return True

if __name__ == "__main__":
    fix_streamlit_code()