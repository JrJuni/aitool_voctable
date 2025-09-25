# VOC 시스템 도커 배포 스크립트 (PowerShell)

Write-Host "🚀 VOC 시스템 도커 배포를 시작합니다..." -ForegroundColor Green

# 환경 변수 파일 확인
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  .env 파일이 없습니다. env.example을 복사하여 .env 파일을 생성하세요." -ForegroundColor Yellow
    Write-Host "   Copy-Item env.example .env" -ForegroundColor Cyan
    Write-Host "   그리고 필요한 값들을 수정하세요." -ForegroundColor Yellow
    exit 1
}

# 도커 및 도커 컴포즈 설치 확인
try {
    docker --version | Out-Null
    docker-compose --version | Out-Null
} catch {
    Write-Host "❌ Docker 또는 Docker Compose가 설치되지 않았습니다." -ForegroundColor Red
    Write-Host "   Docker Desktop을 먼저 설치하세요." -ForegroundColor Yellow
    exit 1
}

# 기존 컨테이너 정리
Write-Host "🧹 기존 컨테이너를 정리합니다..." -ForegroundColor Blue
docker-compose down -v

# 이미지 빌드
Write-Host "🔨 도커 이미지를 빌드합니다..." -ForegroundColor Blue
docker-compose build --no-cache

# 서비스 시작
Write-Host "🚀 서비스를 시작합니다..." -ForegroundColor Blue
docker-compose up -d

# 서비스 상태 확인
Write-Host "⏳ 서비스가 시작될 때까지 대기합니다..." -ForegroundColor Blue
Start-Sleep -Seconds 30

# 헬스체크
Write-Host "🔍 서비스 상태를 확인합니다..." -ForegroundColor Blue
docker-compose ps

# 로그 확인
Write-Host "📋 최근 로그를 확인합니다..." -ForegroundColor Blue
docker-compose logs --tail=50

Write-Host "✅ 배포가 완료되었습니다!" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 접속 정보:" -ForegroundColor Cyan
Write-Host "   - 프론트엔드: http://localhost:8501" -ForegroundColor White
Write-Host "   - 백엔드 API: http://localhost:8000" -ForegroundColor White
Write-Host "   - API 문서: http://localhost:8000/docs" -ForegroundColor White
Write-Host "   - Nginx (HTTPS): https://localhost (SSL 인증서 필요)" -ForegroundColor White
Write-Host ""
Write-Host "📊 관리 명령어:" -ForegroundColor Cyan
Write-Host "   - 로그 확인: docker-compose logs -f" -ForegroundColor White
Write-Host "   - 서비스 중지: docker-compose down" -ForegroundColor White
Write-Host "   - 서비스 재시작: docker-compose restart" -ForegroundColor White
Write-Host "   - 데이터베이스 접속: docker-compose exec mysql mysql -u voc_user -p voc_database" -ForegroundColor White
Write-Host ""
Write-Host "🔐 기본 계정:" -ForegroundColor Cyan
Write-Host "   - HR 관리자: admin@mobilint.com / 0000" -ForegroundColor White
Write-Host "   - 테스트 사용자: kim.chulsoo@mobilint.com / 0000" -ForegroundColor White
