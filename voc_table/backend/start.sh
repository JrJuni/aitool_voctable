#!/bin/bash

# VOC 시스템 백엔드 시작 스크립트

set -e

echo "🚀 VOC 백엔드 서비스를 시작합니다..."

# 데이터베이스 연결 대기
echo "⏳ 데이터베이스 연결을 기다립니다..."
until python -c "
import os
import time
import pymysql
from sqlalchemy import create_engine

# 데이터베이스 URL 가져오기 (환경변수 필수)
db_url = os.environ['DATABASE_URL']

# MySQL 연결 테스트
try:
    # SQLAlchemy 엔진 생성
    engine = create_engine(db_url)
    connection = engine.connect()
    connection.close()
    print('✅ 데이터베이스 연결 성공')
    exit(0)
except Exception as e:
    print(f'❌ 데이터베이스 연결 실패: {e}')
    exit(1)
"; do
    echo "데이터베이스 연결 대기 중..."
    sleep 5
done

# Alembic 마이그레이션 실행
echo "📊 데이터베이스 마이그레이션을 실행합니다..."
alembic upgrade head

# 애플리케이션 시작
echo "🎯 FastAPI 애플리케이션을 시작합니다..."
exec uvicorn app.main_new:app --host 0.0.0.0 --port 8000 --reload
