# CLAUDE.md

이 파일은 Claude Code / Claude Desktop 세션이 이 레포에서 작업할 때 읽는 운영 가이드다.

## Project North Star

**AI VOC(Voice of Customer) 관리 시스템.** 고객 VOC를 수집·조회하고, 회사/연락처/프로젝트와
연결해 관리하는 내부용 웹 애플리케이션. 차별 가치는 세 가지다:

- **JWT 기반 인증 + RBAC**(레벨 0~5) — 승인 워크플로우와 감사로그 포함
- **Streamlit Web UI** — 별도 프론트엔드 빌드 없이 운영 가능한 단일 앱
- **로컬 모델 서빙(llama.cpp)** — 외부 API 없이 온프레미스에서 VOC 요약/추출 (선택적 기능)

스택: FastAPI(백엔드) + Streamlit(프론트엔드) + MySQL + SQLAlchemy/Alembic + Docker + llama.cpp.

## Read First

1. 이 `CLAUDE.md` — 운영 규칙과 아키텍처
2. `README.md` — 빠른 시작과 차별 가치
3. `voc_table/DOCKER_README.md` — Docker 배포 상세
4. `lesson-learned.md` — 과거에 실패/롤백한 작업과 이유 (같은 실수 반복 방지)

## Dev Environment

- OS: Windows 11 / PowerShell. Python 3.11 기준(개발은 3.12에서도 동작).
- 의존성: 루트 `requirements.txt`(AI 포함 전체), `voc_table/backend/requirements.txt`(백엔드 최소),
  `voc_table/frontend/requirements.txt`(프론트). AI 경로(`torch`, `llama-cpp-python`)는 무겁고 선택적이다.
- 시크릿은 **환경변수로만** 주입한다. 코드에 기본값으로 박지 않는다(아래 Architecture Rules).
  로컬 실행 전 `voc_table/env.example`를 복사해 `.env`를 만들고 값을 채운다(`.env`는 커밋 금지).
- Docker 없이 코드를 검증할 때는 가상환경에 백엔드 의존성 서브셋을 설치하고
  더미 env(`JWT_SECRET`, `DATABASE_URL=sqlite:///:memory:`, `DEFAULT_RESET_PW`)를 주입해 `pytest`를 돌린다.

## Working Loop

선호하는 작업 흐름: **plan → implement → test → verify → document → commit.**

- 큰 변경 전에는 plan을 세우고 승인을 받는다.
- 작업 단위(목표)별로 커밋 1회. 파일 하나 고칠 때마다 커밋하지 않는다.
- 검증은 변경 유형에 맞춘다: 문서=리뷰, Python=`py_compile`+`pytest`, YAML=파싱, 시크릿=denylist grep 0건.
- 실 `docker compose up --build` 런타임 검증은 Docker 보유 환경에서 수행한다.

## Architecture

```
voc_table/
├── backend/                      # FastAPI
│   ├── app/
│   │   ├── main_new.py           # ★ canonical 진입점 (모듈러 라우터)
│   │   ├── routers/              # auth, users, voc, companies, contacts, projects, ai, export
│   │   ├── config.py             # 환경설정 단일 출처(settings)
│   │   ├── db.py / db_models.py  # SQLAlchemy 세션 + 6개 테이블
│   │   ├── crud.py / crud_base.py
│   │   ├── schemas.py            # Pydantic
│   │   ├── auth_utils.py / permissions.py / dependencies.py
│   │   ├── excel_io.py           # openpyxl 기반 Excel 내보내기
│   │   ├── filters.py / ai_utils.py / exceptions.py / logging_conf.py
│   │   └── alembic/              # DB 마이그레이션 (스키마는 불변 — 아래 규칙 참조)
│   ├── start.sh / Dockerfile / requirements.txt
├── frontend/streamlit_app.py     # Streamlit 단일 앱 (탭형 UI + 쿠키 인증)
├── mysql/init/                   # 초기 스키마/seed
├── nginx/                        # 리버스 프록시
└── docker-compose.yml            # mysql / migration / backend / frontend / nginx
```

데이터 모델(6 테이블): User, Company, Contact, Project, VOC, AuditLog.

## Architecture Rules

- **시크릿 분리**: JWT 시크릿, DB 자격증명, 관리자 계정, 내부 IP를 코드에 기본값으로 박지 않는다.
  `config.settings`를 단일 출처로 환경변수에서 읽고, 미설정 시 안전하게 실패(fail-fast)하거나 경고한다.
  실계정/실시크릿은 커밋하지 않는다 — `*.example` 파일에 플레이스홀더만 둔다.
- **DB 스키마 불변**: `db_models.py`와 `alembic/versions/*`는 합의 없이 바꾸지 않는다.
  새 Alembic 마이그레이션 생성도 별도 승인 대상이다.
- **진입점 단일화**: `app.main_new`가 canonical이다. 실행 경로(`start.sh`, `run_backend.py`)는 이를 가리킨다.
- **Excel 출력 안전성**: 셀에 쓰는 값은 수식 인젝션 방어(`=,+,-,@` 이스케이프)를 거치고,
  파일명은 안전 문자로 정규화한다(`excel_io.py`의 sanitizer 헬퍼).
- **의존성 보수성**: `requirements.txt`에 없는 패키지를 임의로 추가하지 않는다.

## Docs Convention

- `CLAUDE.md`(이 파일) — 운영 규칙·아키텍처 단일 출처.
- `README.md` — 외부 독자용 소개·빠른 시작.
- `lesson-learned.md` — 실패/롤백 기록만(성공 사례는 적지 않는다).
- 구조가 단순하여 별도 `architecture.md`는 운영하지 않는다.
- 문서는 코드 변경 결과를 반영한다. 변경 후 문서와 코드가 어긋나지 않는지 확인한다.
