-- VOC 데이터베이스 초기화 스크립트

-- 데이터베이스 생성 (이미 docker-compose에서 생성됨)
-- CREATE DATABASE IF NOT EXISTS voc_database;

-- 사용자 권한 설정 (이미 docker-compose에서 설정됨)
-- GRANT ALL PRIVILEGES ON voc_database.* TO 'voc_user'@'%';
-- FLUSH PRIVILEGES;

-- 기본 테이블들은 Alembic 마이그레이션으로 생성됨
-- 여기서는 초기 데이터만 삽입

-- 기본 HR 관리자 계정 (비밀번호: 0000)
-- 실제 사용 시에는 더 강력한 비밀번호로 변경 필요
INSERT IGNORE INTO users (email, name, password_hash, auth_level, is_active, created_at, updated_at) 
VALUES (
    'admin@mobilint.com', 
    'HR Admin', 
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', -- 0000
    5, 
    TRUE, 
    NOW(), 
    NOW()
);

-- 더미 사용자 데이터 (개발/테스트용)
INSERT IGNORE INTO users (email, name, password_hash, auth_level, is_active, created_at, updated_at) 
VALUES 
    ('kim.chulsoo@mobilint.com', '김철수', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', 1, TRUE, NOW(), NOW()),
    ('lee.younghee@mobilint.com', '이영희', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', 2, TRUE, NOW(), NOW()),
    ('park.minsu@mobilint.com', '박민수', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', 3, TRUE, NOW(), NOW()),
    ('choi.jiyoung@mobilint.com', '최지영', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', 2, TRUE, NOW(), NOW()),
    ('jung.suhyun@mobilint.com', '정수현', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8Kz8KzK', 1, TRUE, NOW(), NOW());
