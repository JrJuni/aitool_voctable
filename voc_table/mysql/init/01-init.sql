-- VOC 데이터베이스 초기화 스크립트

-- 데이터베이스 생성 (이미 docker-compose에서 생성됨)
-- CREATE DATABASE IF NOT EXISTS voc_database;

-- 사용자 권한 설정 (이미 docker-compose에서 설정됨)
-- GRANT ALL PRIVILEGES ON voc_database.* TO 'voc_user'@'%';
-- FLUSH PRIVILEGES;

-- 기본 테이블들은 Alembic 마이그레이션으로 생성됨.
--
-- 초기 관리자/사용자 계정은 이 파일에 시드하지 않는다.
-- 실제 비밀번호 해시나 사내 이메일을 레포에 커밋하지 않기 위해서다.
-- 최초 1회, 환경변수(DEFAULT_ADMIN_EMAIL, DEFAULT_RESET_PW)를 설정한 뒤
-- 백엔드의 시드 엔드포인트를 호출해 기본 관리자를 생성한다:
--   POST /admin/setup-default-hr
-- 자세한 내용은 voc_table/env.example 과 README 를 참고한다.
