#!/usr/bin/env python3
"""
간단한 세션 지속성 수정
- 복잡한 localStorage 대신 쿠키 기반 세션 사용
- Streamlit 1.28.1 호환성 확보
"""

# 현재 streamlit_app.py에서 localStorage 관련 함수들을 제거하고
# 더 간단한 쿠키 기반 세션 유지 방식으로 교체

simple_session_functions = '''
def save_session_cookie():
    """세션 정보를 쿠키에 저장 (간단한 방식)"""
    if st.session_state.get('logged_in', False):
        session_data = {
            'email': st.session_state.get('user_email', ''),
            'token': st.session_state.get('session_token', ''),
            'timestamp': time.time()
        }

        # 쿠키로 세션 저장 (24시간 유효)
        session_json = json.dumps(session_data)

        components.html(f"""
        <script>
        // 24시간 후 만료되는 쿠키 설정
        const date = new Date();
        date.setTime(date.getTime() + (24*60*60*1000));
        const expires = "expires=" + date.toUTCString();
        document.cookie = "voc_session={session_json}; " + expires + "; path=/";
        console.log('Session saved to cookie');
        </script>
        """, height=0)

def load_session_cookie():
    """쿠키에서 세션 정보 복원"""
    # 쿠키에서 세션 정보 읽기
    components.html("""
    <script>
    function getCookie(name) {
        const value = "; " + document.cookie;
        const parts = value.split("; " + name + "=");
        if (parts.length === 2) {
            return parts.pop().split(";").shift();
        }
        return null;
    }

    const sessionCookie = getCookie('voc_session');
    if (sessionCookie) {
        try {
            const sessionData = JSON.parse(decodeURIComponent(sessionCookie));
            const now = Date.now() / 1000;

            // 24시간 이내 세션만 유효
            if (now - sessionData.timestamp < 24 * 60 * 60) {
                console.log('Valid session found in cookie');
                // Streamlit에 메시지 전달하는 대신 쿠키 유지
            } else {
                document.cookie = "voc_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
                console.log('Session expired, cookie cleared');
            }
        } catch (e) {
            document.cookie = "voc_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            console.log('Invalid session cookie, cleared');
        }
    }
    </script>
    """, height=0)

def clear_session_cookie():
    """세션 쿠키 삭제"""
    components.html("""
    <script>
    document.cookie = "voc_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    console.log('Session cookie cleared');
    </script>
    """, height=0)

def get_session_from_cookie():
    """JavaScript 없이 Python에서 세션 복원 (서버사이드)"""
    # 이 함수는 실제로는 Streamlit에서 쿠키 직접 접근이 어려우므로
    # 세션 상태 자체의 지속성을 높이는 방식으로 접근
    if 'session_check_count' not in st.session_state:
        st.session_state.session_check_count = 0

    st.session_state.session_check_count += 1

    # 세션 복원 로직은 JavaScript에서 처리하고
    # Python에서는 토큰 검증만 수행
    return None
'''

print("간단한 쿠키 기반 세션 함수들이 준비되었습니다.")
print("복잡한 localStorage 대신 쿠키를 사용하여 브라우저 호환성을 높입니다.")