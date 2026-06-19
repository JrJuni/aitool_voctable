#!/usr/bin/env python3
"""
VOC Table Backend Server 실행 스크립트
"""
import uvicorn
import os
import sys

# 프로젝트 루트 디렉토리를 Python 경로에 추가
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

if __name__ == "__main__":
    print("🚀 VOC Table Backend Server 시작 중...")
    print("📍 로컬 서버 주소: http://localhost:8000")
    print("📚 API 문서: http://localhost:8000/docs")
    print("⏹️  서버 중지: Ctrl+C")
    print("-" * 50)
    
    try:
        uvicorn.run(
            "backend.app.main_new:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n🛑 서버가 중지되었습니다.")
    except Exception as e:
        print(f"❌ 서버 실행 중 오류 발생: {e}")
        print("💡 해결 방법:")
        print("   1. 필요한 패키지가 설치되어 있는지 확인: pip install -r requirements.txt")
        print("   2. 데이터베이스가 설정되어 있는지 확인")
        print("   3. 포트 8000이 사용 중이지 않은지 확인")
