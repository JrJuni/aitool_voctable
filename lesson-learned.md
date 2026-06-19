# Lesson Learned

실패하거나 롤백한 작업만 기록한다(성공 사례는 적지 않는다).
형식: **시도한 것 / 실패 원인 / 해결 또는 포기 이유**.

---

## 1. Docker 검증 게이트를 그대로 실행하지 못함

- **시도한 것**: 가드레일대로 각 작업 단위 후 `docker compose up --build` 성공을 검증 게이트로 삼으려 함.
- **실패 원인**: 작업 환경에 Docker가 설치되어 있지 않음(`docker: command not found`).
  게다가 백엔드 의존성의 `torch`/`llama-cpp-python` 빌드는 다중 GB·장시간이라 2시간 룰에도 저촉.
- **해결**: 변경 유형별 대체 검증으로 스케일 — 가상환경에 의존성 서브셋(AI 제외) 설치 후 `pytest`/`py_compile`,
  `yaml.safe_load`로 compose/workflow 파싱, denylist grep, route-parity 비교.
  실제 `docker compose up --build` 런타임 검증은 Docker 보유 환경에서 사용자가 별도 수행하도록 README에 명시.

## 2. 의존성 핀 버전 불일치로 거짓 결론 직전까지 감

- **시도한 것**: route-parity 점검을 위해 `fastapi`/`starlette`를 **핀 없이** 설치하고 main vs main_new 라우트 비교.
- **실패 원인**: 설치된 `starlette 1.3.1`이 프로젝트 핀 `0.48.0`과 major 차이라 `include_router` 동작이 달라,
  main_new가 6개 라우트만 노출하는 것처럼 측정됨 → "모듈러 리팩터가 미완성/깨짐"이라는 **거짓 판정** 직전까지 감.
  (`pandas`도 3.0.3이 깔려 핀 2.3.2와 불일치)
- **해결**: 핀 버전(`fastapi==0.117.1`, `starlette==0.48.0`, `pandas==2.3.2`, `openpyxl==3.1.5`) 재설치 후 재측정 →
  실제로는 68/70 라우트의 거의 완전한 리팩터로 확인. **교훈: 라이브러리 동작으로 결론 내리기 전 프로젝트 핀 버전으로 검증한다.**

## 3. gitignore된 경로의 추적 해제에서 `git add` 거부

- **시도한 것**: 커밋된 `logs/*.txt`의 제거를 `git add`로 스테이징.
- **실패 원인**: `logs/`가 이미 `.gitignore`에 있어 `git add`가 무시(거부).
- **해결**: 추적 파일의 삭제 기록은 `git rm --cached`로 처리(작업 트리 파일은 유지하면서 추적만 해제).

## 4. 기존 테스트가 pytest로 실행되지 않는 상태(베이스라인)

- **시도한 것**: Step 0에서 기존 `voc_table/tests/`를 베이스라인으로 실행.
- **실패 원인**: `test_excel_export_database.py::test_excel_exports`가 정의되지 않은 `db` 픽스처를 요구해 ERROR,
  나머지는 `if __name__ == "__main__"` 스크립트라 pytest 수집 0건.
- **해결/포기**: 본 작업 범위(시크릿/문서/위생/sanitizer)에서 기존 테스트 리팩터는 범위 밖으로 두고,
  새 `test_excel_sanitizer.py`만 실제 통과하도록 작성. 기존 테스트의 픽스처 정비는 후속 작업으로 남김(TODO).

---

## CI 반영 (`.github/workflows/ci.yml`와 1:1 매칭)

- [x] CI: 시크릿 denylist 스캔 (`secret-scan` 잡) — 추적 파일에서 알려진 시크릿/PII 0건 강제
- [x] CI: `docker compose config` 검증 (`compose-validate` 잡, 더미 env 주입)
- [x] CI: `pytest` 실행 (`test` 잡, fail-fast 대응 더미 env 주입)
- [x] CI: `ruff` 린트 (`lint` 잡, requirements 미포함이라 비차단 opt-in)

---

## 후속(TODO)

- 삭제한 `main.py`에만 있던 변형 라우트 3개의 재이식 여부 검토:
  `POST /users/`(생성, `/users/register`로 대체됨), `PATCH /users/me/admin-profile`,
  `PATCH /users/{user_id}/reset-password-admin`.
- 기존 스캐폴드 테스트(`test_excel_export_database.py` 등)의 `db` 픽스처/conftest 정비.
