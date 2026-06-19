# VOC Table

고객 VOC(Voice of Customer)를 수집·조회하고 회사/연락처/프로젝트와 연결해 관리하는 내부용 웹 애플리케이션.

## 차별 가치

- **JWT 인증 + RBAC** — 토큰 기반 인증, 권한 레벨 0~5, 승인 워크플로우와 감사로그.
- **Streamlit Web UI** — 별도 프론트엔드 빌드 없이 운영 가능한 단일 웹 앱.
- **로컬 모델 서빙(llama.cpp)** — 외부 API 없이 온프레미스에서 VOC 요약/추출(선택적 기능).

스택: FastAPI · Streamlit · MySQL · SQLAlchemy/Alembic · Docker · llama.cpp

## 빠른 시작 (Docker)

```bash
git clone https://github.com/JrJuni/aitool_voctable.git
cd aitool_voctable/voc_table

# 환경변수 설정 (실제 값으로 채운 뒤 .env로 저장 — .env는 커밋하지 않는다)
cp env.example .env

# 전체 스택 기동
docker compose up --build
```

- 프론트엔드: http://localhost:8501
- 백엔드 API / 문서: http://localhost:8000/docs

> 시크릿(JWT_SECRET, DATABASE_URL, MYSQL_*, DEFAULT_RESET_PW 등)은 환경변수로만 주입한다.
> 미설정 시 백엔드는 안전하게 기동을 거부한다(코드에 기본값을 두지 않음). 필요한 키는 `voc_table/env.example` 참고.

## 로컬 실행 (Docker 없이)

```bash
cd voc_table
pip install -r backend/requirements.txt   # AI 기능 제외 시 torch/llama-cpp는 생략 가능
python run_backend.py     # FastAPI (app.main_new)
python run_frontend.py    # Streamlit
```

## 기본 관리자 계정

레포에는 실계정을 시드하지 않는다. 최초 1회 `.env`에 `DEFAULT_ADMIN_EMAIL`과 `DEFAULT_RESET_PW`를
설정한 뒤 시드 엔드포인트로 관리자를 생성한다:

```bash
curl -X POST http://localhost:8000/admin/setup-default-hr
```

CLI 시드용 자격 파일은 `voc_table/create_admin.example.json`을 복사해 사용한다.

## 아키텍처 한눈에

```
voc_table/
├── backend/app/
│   ├── main_new.py        # FastAPI 진입점 (모듈러 라우터)
│   ├── routers/           # auth, users, voc, companies, contacts, projects, ai, export
│   ├── config.py          # 환경설정 단일 출처 (시크릿은 env에서만)
│   ├── db.py, db_models.py, crud.py, schemas.py
│   ├── auth_utils.py, permissions.py, dependencies.py
│   ├── excel_io.py        # Excel 내보내기 (수식 인젝션 방어 포함)
│   └── alembic/           # DB 마이그레이션
├── frontend/streamlit_app.py
├── mysql/init/            # 초기 스키마
├── nginx/
└── docker-compose.yml     # mysql / migration / backend / frontend / nginx
```

데이터 모델: User, Company, Contact, Project, VOC, AuditLog.

## 개발 / 검증

- 운영 규칙과 아키텍처 상세는 [`CLAUDE.md`](CLAUDE.md) 참고.
- CI(`.github/workflows/ci.yml`): 시크릿 denylist 스캔, `pytest`, `docker compose config` 검증.
- 과거 실패/롤백 기록은 [`lesson-learned.md`](lesson-learned.md) 참고.

## 라이선스

[LICENSE](LICENSE) 참고.
