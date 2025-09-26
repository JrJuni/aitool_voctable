#!/usr/bin/env python3
"""
쿠키 기반 세션 유지 수정
- localStorage 대신 쿠키 사용
- 브라우저 호환성 개선
"""

import streamlit as st
import streamlit.components.v1 as components
import json
import time

def save_session_to_cookie():
    """세션을 쿠키에 저장"""
    if st.session_state.get('logged_in', False):
        session_data = {
            'user_email': st.session_state.get('user_email', ''),
            'username': st.session_state.get('username', ''),
            'auth_level': st.session_state.get('auth_level', 0),
            'session_token': st.session_state.get('session_token', ''),
            'profile_department': st.session_state.get('profile_department', '전략팀'),
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

def load_session_from_cookie():
    """쿠키에서 세션 정보 복원"""
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
                // Streamlit에 세션 데이터 전달
                window.parent.postMessage({
                    type: 'session_restore',
                    data: sessionData
                }, '*');
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

# 사용법:
# 1. streamlit_app.py에서 localStorage 함수들을 이 쿠키 함수들로 교체
# 2. save_session_to_localStorage() → save_session_to_cookie()
# 3. load_session_from_localStorage() → load_session_from_cookie()  
# 4. clear_localStorage() → clear_session_cookie()
