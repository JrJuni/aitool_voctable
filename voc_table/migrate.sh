#!/bin/bash

# VOC 시스템 데이터베이스 마이그레이션 스크립트

set -e

echo "📊 VOC 시스템 데이터베이스 마이그레이션을 시작합니다..."

# 환경 변수 파일 확인
if [ ! -f ".env" ]; then
    echo "⚠️  .env 파일이 없습니다. env.example을 복사하여 .env 파일을 생성하세요."
    echo "   cp env.example .env"
    exit 1
fi

# 도커 컨테이너가 실행 중인지 확인
if ! docker-compose ps | grep -q "voc_mysql"; then
    echo "❌ MySQL 컨테이너가 실행되지 않았습니다."
    echo "   먼저 'docker-compose up -d mysql'을 실행하세요."
    exit 1
fi

# 마이그레이션 실행
echo "🔄 데이터베이스 마이그레이션을 실행합니다..."
docker-compose run --rm migration

echo "✅ 마이그레이션이 완료되었습니다!"

# 마이그레이션 상태 확인
echo "📋 현재 마이그레이션 상태:"
docker-compose run --rm migration alembic current

echo ""
echo "📊 사용 가능한 명령어:"
echo "   - 마이그레이션 상태 확인: docker-compose run --rm migration alembic current"
echo "   - 마이그레이션 히스토리: docker-compose run --rm migration alembic history"
echo "   - 새 마이그레이션 생성: docker-compose run --rm migration alembic revision --autogenerate -m '설명'"
echo "   - 특정 리비전으로 다운그레이드: docker-compose run --rm migration alembic downgrade <revision>"
