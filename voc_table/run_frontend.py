#!/usr/bin/env python3
"""
VOC Table Frontend 실행 스크립트
"""
import subprocess
import sys
import os

def run_streamlit():
    """Streamlit 앱 실행"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    frontend_path = os.path.join(project_root, "frontend", "streamlit_app.py")
    
    print("🌐 VOC Table Frontend 시작 중...")
    print("📍 로컬 앱 주소: http://localhost:8501")
    print("⏹️  앱 중지: Ctrl+C")
    print("-" * 50)
    
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            frontend_path,
            "--server.port", "8501",
            "--server.address", "0.0.0.0"  # 모든 네트워크 인터페이스에서 접근 가능
        ])
    except KeyboardInterrupt:
        print("\n🛑 앱이 중지되었습니다.")
    except Exception as e:
        print(f"❌ 앱 실행 중 오류 발생: {e}")
        print("💡 해결 방법:")
        print("   1. Streamlit이 설치되어 있는지 확인: pip install streamlit")
        print("   2. 필요한 패키지가 설치되어 있는지 확인: pip install -r requirements.txt")
        print("   3. 포트 8501이 사용 중이지 않은지 확인")

if __name__ == "__main__":
    run_streamlit()
