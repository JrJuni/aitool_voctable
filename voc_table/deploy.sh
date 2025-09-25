#!/bin/bash

# VOC 시스템 도커 배포 스크립트

set -e

echo "🚀 VOC 시스템 도커 배포를 시작합니다..."

# 환경 변수 파일 확인
if [ ! -f ".env" ]; then
    echo "⚠️  .env 파일이 없습니다. env.example을 복사하여 .env 파일을 생성하세요."
    echo "   cp env.example .env"
    echo "   그리고 필요한 값들을 수정하세요."
    exit 1
fi

# 도커 및 도커 컴포즈 설치 확인
if ! command -v docker &> /dev/null; then
    echo "❌ Docker가 설치되지 않았습니다. Docker를 먼저 설치하세요."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose가 설치되지 않았습니다. Docker Compose를 먼저 설치하세요."
    exit 1
fi

# 기존 컨테이너 정리
echo "🧹 기존 컨테이너를 정리합니다..."
docker-compose down -v

# 이미지 빌드
echo "🔨 도커 이미지를 빌드합니다..."
docker-compose build --no-cache

# 서비스 시작
echo "🚀 서비스를 시작합니다..."
docker-compose up -d

# 서비스 상태 확인
echo "⏳ 서비스가 시작될 때까지 대기합니다..."
sleep 30

# 헬스체크
echo "🔍 서비스 상태를 확인합니다..."
docker-compose ps

# 로그 확인
echo "📋 최근 로그를 확인합니다..."
docker-compose logs --tail=50

echo "✅ 배포가 완료되었습니다!"
echo ""
echo "🌐 접속 정보:"
echo "   - 프론트엔드: http://localhost:8501"
echo "   - 백엔드 API: http://localhost:8000"
echo "   - API 문서: http://localhost:8000/docs"
echo "   - Nginx (HTTPS): https://localhost (SSL 인증서 필요)"
echo ""
echo "📊 관리 명령어:"
echo "   - 로그 확인: docker-compose logs -f"
echo "   - 서비스 중지: docker-compose down"
echo "   - 서비스 재시작: docker-compose restart"
echo "   - 데이터베이스 접속: docker-compose exec mysql mysql -u voc_user -p voc_database"
echo ""
echo "🔐 기본 계정:"
echo "   - HR 관리자: admin@mobilint.com / 0000"
echo "   - 테스트 사용자: kim.chulsoo@mobilint.com / 0000"
