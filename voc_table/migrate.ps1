# VOC 시스템 데이터베이스 마이그레이션 스크립트 (PowerShell)

Write-Host "📊 VOC 시스템 데이터베이스 마이그레이션을 시작합니다..." -ForegroundColor Green

# 환경 변수 파일 확인
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  .env 파일이 없습니다. env.example을 복사하여 .env 파일을 생성하세요." -ForegroundColor Yellow
    Write-Host "   Copy-Item env.example .env" -ForegroundColor Cyan
    exit 1
}

# 도커 컨테이너가 실행 중인지 확인
$mysqlStatus = docker-compose ps | Select-String "voc_mysql"
if (-not $mysqlStatus) {
    Write-Host "❌ MySQL 컨테이너가 실행되지 않았습니다." -ForegroundColor Red
    Write-Host "   먼저 'docker-compose up -d mysql'을 실행하세요." -ForegroundColor Yellow
    exit 1
}

# 마이그레이션 실행
Write-Host "🔄 데이터베이스 마이그레이션을 실행합니다..." -ForegroundColor Blue
docker-compose run --rm migration

Write-Host "✅ 마이그레이션이 완료되었습니다!" -ForegroundColor Green

# 마이그레이션 상태 확인
Write-Host "📋 현재 마이그레이션 상태:" -ForegroundColor Cyan
docker-compose run --rm migration alembic current

Write-Host ""
Write-Host "📊 사용 가능한 명령어:" -ForegroundColor Cyan
Write-Host "   - 마이그레이션 상태 확인: docker-compose run --rm migration alembic current" -ForegroundColor White
Write-Host "   - 마이그레이션 히스토리: docker-compose run --rm migration alembic history" -ForegroundColor White
Write-Host "   - 새 마이그레이션 생성: docker-compose run --rm migration alembic revision --autogenerate -m '설명'" -ForegroundColor White
Write-Host "   - 특정 리비전으로 다운그레이드: docker-compose run --rm migration alembic downgrade <revision>" -ForegroundColor White
