# VOC 시스템 내부망 접속 설정 스크립트
# 관리자 권한으로 실행해야 합니다.

Write-Host "🌐 VOC 시스템 내부망 접속 설정" -ForegroundColor Green
Write-Host "=" * 50

# 현재 IP 주소 확인
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like "172.16.*"}).IPAddress
Write-Host "📍 현재 IP 주소: $ipAddress" -ForegroundColor Yellow

# 방화벽 규칙 추가
Write-Host "`n🔧 방화벽 규칙 설정 중..." -ForegroundColor Cyan

try {
    # 백엔드 API 포트 (8000)
    netsh advfirewall firewall add rule name="VOC Backend API" dir=in action=allow protocol=TCP localport=8000
    Write-Host "✅ 백엔드 API 포트 (8000) 방화벽 규칙 추가 완료" -ForegroundColor Green
    
    # 프론트엔드 Streamlit 포트 (8501)
    netsh advfirewall firewall add rule name="VOC Frontend Streamlit" dir=in action=allow protocol=TCP localport=8501
    Write-Host "✅ 프론트엔드 Streamlit 포트 (8501) 방화벽 규칙 추가 완료" -ForegroundColor Green
    
} catch {
    Write-Host "❌ 방화벽 규칙 추가 실패: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "💡 수동으로 방화벽 설정을 해주세요:" -ForegroundColor Yellow
    Write-Host "   - Windows 방화벽 > 고급 설정 > 인바운드 규칙 > 새 규칙" -ForegroundColor Yellow
    Write-Host "   - 포트: TCP 8000, 8501 허용" -ForegroundColor Yellow
}

Write-Host "`n📋 접속 정보:" -ForegroundColor Cyan
Write-Host "   백엔드 API: http://$ipAddress:8000" -ForegroundColor White
Write-Host "   프론트엔드: http://$ipAddress:8501" -ForegroundColor White
Write-Host "   API 문서: http://$ipAddress:8000/docs" -ForegroundColor White

Write-Host "`n🚀 서버 실행 방법:" -ForegroundColor Cyan
Write-Host "   1. 백엔드: python run_backend.py" -ForegroundColor White
Write-Host "   2. 프론트엔드: python run_frontend.py" -ForegroundColor White

Write-Host "`n👥 다른 사용자 접속 방법:" -ForegroundColor Cyan
Write-Host "   브라우저에서 http://$ipAddress:8501 접속" -ForegroundColor White

Write-Host "`n⚠️  주의사항:" -ForegroundColor Yellow
Write-Host "   - 내부망에서만 접속 가능합니다" -ForegroundColor White
Write-Host "   - 보안을 위해 외부망 접속은 차단됩니다" -ForegroundColor White
Write-Host "   - 사용자 인증이 필요합니다" -ForegroundColor White

Write-Host "`n✅ 설정 완료!" -ForegroundColor Green
