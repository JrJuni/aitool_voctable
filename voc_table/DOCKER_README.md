# VOC 시스템 도커 배포 가이드

## 📋 개요

이 문서는 VOC 시스템을 Docker를 사용하여 배포하는 방법을 설명합니다.

## 🏗️ 시스템 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nginx         │    │   Frontend      │    │   Backend       │
│   (Port 80/443) │────│   (Streamlit)   │────│   (FastAPI)     │
│                 │    │   (Port 8501)   │    │   (Port 8000)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                               ┌─────────────────┐
                                               │   MySQL         │
                                               │   (Port 3306)   │
                                               └─────────────────┘
```

## 🚀 빠른 시작

### 1. 사전 요구사항

- Docker Desktop (Windows/Mac) 또는 Docker Engine (Linux)
- Docker Compose
- 최소 4GB RAM 권장

### 2. 환경 설정

```bash
# 환경 변수 파일 복사
cp env.example .env

# .env 파일 편집 (필요시)
# - JWT_SECRET: 보안을 위해 강력한 비밀키로 변경
# - MYSQL_PASSWORD: 데이터베이스 비밀번호 변경
# - 기타 설정값들 확인
```

### 3. 배포 실행

#### Windows (PowerShell)
```powershell
.\deploy.ps1
```

#### Linux/Mac (Bash)
```bash
./deploy.sh
```

#### 수동 배포
```bash
# 기존 컨테이너 정리
docker-compose down -v

# 이미지 빌드 및 서비스 시작
docker-compose up -d --build

# 로그 확인
docker-compose logs -f
```

## 🌐 접속 정보

배포 완료 후 다음 URL로 접속할 수 있습니다:

- **프론트엔드**: http://localhost:8501
- **백엔드 API**: http://localhost:8000
- **API 문서**: http://localhost:8000/docs
- **Nginx (HTTPS)**: https://localhost (SSL 인증서 설정 필요)

## 🔐 기본 계정

기본 계정은 레포에 시드하지 않는다. 최초 1회 `.env`에 `DEFAULT_ADMIN_EMAIL`과
`DEFAULT_RESET_PW`를 설정한 뒤, 백엔드의 시드 엔드포인트로 관리자를 생성한다:

```bash
curl -X POST http://localhost:8000/admin/setup-default-hr
```

- 생성되는 관리자 이메일: `DEFAULT_ADMIN_EMAIL` (권한 레벨 5)
- 초기 비밀번호: `DEFAULT_RESET_PW` (최초 로그인 후 변경 권장)

## 📊 관리 명령어

### 서비스 관리
```bash
# 서비스 상태 확인
docker-compose ps

# 로그 확인
docker-compose logs -f

# 특정 서비스 로그 확인
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f mysql

# 서비스 재시작
docker-compose restart

# 서비스 중지
docker-compose down

# 서비스 중지 (볼륨 포함)
docker-compose down -v
```

### 데이터베이스 관리
```bash
# MySQL 컨테이너 접속
docker-compose exec mysql bash

# MySQL 클라이언트 접속
docker-compose exec mysql mysql -u voc_user -p voc_database

# 데이터베이스 백업
docker-compose exec mysql mysqldump -u voc_user -p voc_database > backup.sql

# 데이터베이스 복원
docker-compose exec -T mysql mysql -u voc_user -p voc_database < backup.sql
```

### Alembic 마이그레이션 관리
```bash
# 마이그레이션 실행
./migrate.sh  # Linux/Mac
.\migrate.ps1  # Windows

# 또는 수동으로 실행
docker-compose run --rm migration

# 마이그레이션 상태 확인
docker-compose run --rm migration alembic current

# 마이그레이션 히스토리 확인
docker-compose run --rm migration alembic history

# 새 마이그레이션 생성 (모델 변경 후)
docker-compose run --rm migration alembic revision --autogenerate -m "설명"

# 특정 리비전으로 다운그레이드
docker-compose run --rm migration alembic downgrade <revision>
```

### 이미지 관리
```bash
# 이미지 재빌드
docker-compose build --no-cache

# 특정 서비스만 재빌드
docker-compose build --no-cache backend

# 사용하지 않는 이미지 정리
docker system prune -a
```

## 🔧 설정 파일

### 환경 변수 (.env)
```env
# 데이터베이스 설정 (값은 voc_table/env.example 참고, 실제 비밀번호로 채울 것)
DATABASE_URL=replace-with-db-url
MYSQL_ROOT_PASSWORD=replace-with-root-password
MYSQL_DATABASE=voc_database
MYSQL_USER=voc_user
MYSQL_PASSWORD=replace-with-db-password

# JWT 설정
JWT_SECRET=replace-with-a-long-random-secret
TOKEN_EXPIRE_MIN=30

# 로깅 설정
LOG_LEVEL=INFO
```

### Docker Compose 서비스

#### MySQL
- **이미지**: mysql:8.0
- **포트**: 3306
- **볼륨**: mysql_data (데이터 영속성)
- **초기화**: mysql/init/01-init.sql

#### Backend (FastAPI)
- **포트**: 8000
- **환경**: Python 3.11-slim
- **의존성**: requirements.txt
- **헬스체크**: /health 엔드포인트

#### Frontend (Streamlit)
- **포트**: 8501
- **환경**: Python 3.11-slim
- **의존성**: requirements.txt
- **헬스체크**: /_stcore/health 엔드포인트

#### Nginx (선택사항)
- **포트**: 80, 443
- **역할**: 리버스 프록시, SSL 터미네이션
- **설정**: nginx/nginx.conf

## 🛠️ 개발 환경

### 로컬 개발
```bash
# 개발 모드로 실행 (코드 변경 시 자동 재시작)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# 특정 서비스만 실행
docker-compose up backend mysql
```

### 디버깅
```bash
# 컨테이너 내부 접속
docker-compose exec backend bash
docker-compose exec frontend bash

# 실시간 로그 모니터링
docker-compose logs -f --tail=100
```

## 🔒 보안 고려사항

### 프로덕션 배포 시 필수 사항

1. **환경 변수 보안**
   - JWT_SECRET을 강력한 랜덤 키로 변경
   - 데이터베이스 비밀번호를 복잡하게 설정
   - .env 파일을 .gitignore에 추가

2. **SSL 인증서**
   - Let's Encrypt 또는 상용 인증서 사용
   - nginx/ssl/ 디렉토리에 인증서 배치

3. **방화벽 설정**
   - 필요한 포트만 외부에 노출
   - 데이터베이스 포트(3306)는 내부 네트워크만 접근 가능

4. **정기 백업**
   - 데이터베이스 정기 백업 스크립트 설정
   - 로그 파일 로테이션 설정

## 🐛 문제 해결

### 일반적인 문제

#### 1. 포트 충돌
```bash
# 포트 사용 중인 프로세스 확인
netstat -tulpn | grep :8000
netstat -tulpn | grep :8501
netstat -tulpn | grep :3306

# docker-compose.yml에서 포트 변경
ports:
  - "8001:8000"  # 8000 대신 8001 사용
```

#### 2. 메모리 부족
```bash
# Docker 메모리 제한 확인
docker stats

# docker-compose.yml에 메모리 제한 추가
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 1G
```

#### 3. 데이터베이스 연결 실패
```bash
# MySQL 컨테이너 상태 확인
docker-compose logs mysql

# 네트워크 연결 테스트
docker-compose exec backend ping mysql
```

#### 4. 이미지 빌드 실패
```bash
# 캐시 없이 재빌드
docker-compose build --no-cache

# 특정 단계부터 재빌드
docker-compose build --no-cache --build-arg BUILDKIT_INLINE_CACHE=1
```

## 📈 모니터링

### 헬스체크
```bash
# 서비스 헬스체크 상태 확인
curl http://localhost:8000/health
curl http://localhost:8501/_stcore/health
```

### 리소스 모니터링
```bash
# 컨테이너 리소스 사용량
docker stats

# 디스크 사용량
docker system df
```

## 📞 지원

문제가 발생하거나 추가 도움이 필요한 경우:

1. 로그 파일 확인: `docker-compose logs`
2. 시스템 상태 확인: `docker-compose ps`
3. 리소스 사용량 확인: `docker stats`
4. 이슈 리포트 작성 시 위 정보들을 포함해 주세요.

---

**참고**: 이 가이드는 개발 및 테스트 환경을 기준으로 작성되었습니다. 프로덕션 환경에서는 추가적인 보안 설정과 모니터링이 필요합니다.
