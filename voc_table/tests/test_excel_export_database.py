#!/usr/bin/env python3
"""
===========================================
VOC Table Excel Export 기능 데이터베이스 테스트
===========================================

목적:
- excel_io.py의 모든 export 함수들을 실제 데이터베이스와 연동하여 테스트
- SQLAlchemy ORM을 사용한 실제 데이터베이스 환경에서의 export 기능 검증
- export_voc_to_excel, export_full_tables_to_excel, export_all_tables_to_excel 함수 테스트
- 데이터베이스 조인, 관계형 데이터 처리 등 실제 운영 환경과 유사한 테스트

테스트 내용:
1. SQLite 메모리 데이터베이스 생성 및 테이블 생성
2. 테스트 데이터 생성 (User, Company, Contact, Project, VOC, AuditLog)
3. VOC 전용 export (company_id 제외, company_name 추가)
4. Full tables export (Users 제외, 연동 ID 제외)
5. All tables export (모든 테이블 포함)

사용법:
    python test_excel_export_database.py

생성 파일:
- export_voc_YYMMDD_HHMM.xlsx (VOC 전용)
- export_full_YYMMDD_HHMM.xlsx (전체 테이블, Users 제외)
- export_all_YYMMDD_HHMM.xlsx (모든 테이블)
"""
import sys
import os
from datetime import datetime, date
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 프로젝트 루트를 Python 경로에 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.db_models import Base, User, Company, Contact, Project, VOC, AuditLog
from backend.app.excel_io import export_voc_to_excel, export_full_tables_to_excel, export_all_tables_to_excel

def create_test_database():
    """테스트용 SQLite 데이터베이스 생성"""
    # SQLite 메모리 데이터베이스 생성
    engine = create_engine("sqlite:///:memory:", echo=False)
    
    # 테이블 생성
    Base.metadata.create_all(bind=engine)
    
    # 세션 생성
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()

def create_test_data(db):
    """테스트 데이터 생성"""
    print("테스트 데이터 생성 중...")
    
    # 사용자 데이터
    users = [
        User(
            email="admin@mobilint.com",
            username="admin",
            hashed_password="hashed_password_123",
            auth_level=5,
            is_active=True,
            department="IT",
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        User(
            email="user1@mobilint.com",
            username="user1",
            hashed_password="hashed_password_123",
            auth_level=2,
            is_active=True,
            department="Sales",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]
    
    for user in users:
        db.add(user)
    db.commit()
    
    # 회사 데이터
    companies = [
        Company(
            name="삼성전자",
            domain="samsung.com",
            revenue="1000억",
            employee=50000,
            nation="한국",
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        Company(
            name="LG전자",
            domain="lg.com",
            revenue="500억",
            employee=25000,
            nation="한국",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]
    
    for company in companies:
        db.add(company)
    db.commit()
    
    # 연락처 데이터
    contacts = [
        Contact(
            name="김철수",
            title="부장",
            email="kim.cs@samsung.com",
            phone="010-1234-5678",
            note="삼성전자 담당자",
            company_id=1,
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        Contact(
            name="이영희",
            title="과장",
            email="lee.yh@lg.com",
            phone="010-9876-5432",
            note="LG전자 담당자",
            company_id=2,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]
    
    for contact in contacts:
        db.add(contact)
    db.commit()
    
    # 프로젝트 데이터
    projects = [
        Project(
            name="AI 칩 개발 프로젝트",
            field="반도체",
            target_app="스마트폰",
            ai_model="GPT-4",
            perf="고성능",
            power="저전력",
            size="소형",
            price="경쟁력 있는 가격",
            requirements="고성능 AI 처리",
            competitors="애플, 구글",
            result="성공",
            root_cause="기술력 우위",
            company_id=1,
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        Project(
            name="스마트홈 솔루션",
            field="IoT",
            target_app="스마트홈",
            ai_model="BERT",
            perf="중간 성능",
            power="저전력",
            size="중형",
            price="합리적 가격",
            requirements="안정적인 IoT 연결",
            competitors="삼성, SK텔레콤",
            result="진행중",
            root_cause="시장 수요 증가",
            company_id=2,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]
    
    for project in projects:
        db.add(project)
    db.commit()
    
    # VOC 데이터
    vocs = [
        VOC(
            date=date.today(),
            content="AI 칩 성능이 기대보다 낮습니다. 개선이 필요합니다.",
            action_item="성능 최적화 작업 진행",
            due_date=date(2025, 2, 15),
            status="in_progress",
            priority="high",
            assignee_user_id=1,
            company_id=1,
            contact_id=1,
            project_id=1,
            ai_summary="AI 칩 성능 개선 요청",
            created_at=datetime.now(),
            updated_at=datetime.now()
        ),
        VOC(
            date=date.today(),
            content="스마트홈 솔루션의 가격이 너무 비쌉니다.",
            action_item="가격 재검토 및 조정",
            due_date=date(2025, 2, 20),
            status="pending",
            priority="medium",
            assignee_user_id=2,
            company_id=2,
            contact_id=2,
            project_id=2,
            ai_summary="가격 경쟁력 개선 요청",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    ]
    
    for voc in vocs:
        db.add(voc)
    db.commit()
    
    # 감사 로그 데이터
    audit_logs = [
        AuditLog(
            actor_user_id=1,
            action="create",
            table_name="vocs",
            row_id=1,
            after_json={"content": "AI 칩 성능이 기대보다 낮습니다."},
            ip="127.0.0.1",
            ua="Test Browser",
            created_at=datetime.now()
        ),
        AuditLog(
            actor_user_id=2,
            action="create",
            table_name="vocs",
            row_id=2,
            after_json={"content": "스마트홈 솔루션의 가격이 너무 비쌉니다."},
            ip="127.0.0.1",
            ua="Test Browser",
            created_at=datetime.now()
        )
    ]
    
    for audit_log in audit_logs:
        db.add(audit_log)
    db.commit()
    
    print("테스트 데이터 생성 완료!")
    print(f"- 사용자: {len(users)}명")
    print(f"- 회사: {len(companies)}개")
    print(f"- 연락처: {len(contacts)}개")
    print(f"- 프로젝트: {len(projects)}개")
    print(f"- VOC: {len(vocs)}개")
    print(f"- 감사 로그: {len(audit_logs)}개")

def test_excel_exports(db):
    """엑셀 export 기능 테스트"""
    print("\n=== 엑셀 Export 테스트 시작 ===")
    
    try:
        # 1. VOC 전용 export 테스트
        print("\n1. VOC 전용 export 테스트...")
        voc_file = export_voc_to_excel(db)
        print(f"✅ VOC export 완료: {voc_file}")
        
        # 2. Full tables export 테스트 (Users 제외)
        print("\n2. Full tables export 테스트 (Users 제외)...")
        full_file = export_full_tables_to_excel(db)
        print(f"✅ Full export 완료: {full_file}")
        
        # 3. All tables export 테스트 (기존 기능)
        print("\n3. All tables export 테스트 (모든 테이블)...")
        all_file = export_all_tables_to_excel(db)
        print(f"✅ All export 완료: {all_file}")
        
        print("\n=== 모든 테스트 완료! ===")
        print(f"생성된 파일들:")
        print(f"- VOC 전용: {os.path.basename(voc_file)}")
        print(f"- Full (Users 제외): {os.path.basename(full_file)}")
        print(f"- All (모든 테이블): {os.path.basename(all_file)}")
        
    except Exception as e:
        print(f"❌ 테스트 실패: {str(e)}")
        import traceback
        traceback.print_exc()

def main():
    """메인 함수"""
    print("엑셀 Export 기능 테스트 시작...")
    
    # 테스트 데이터베이스 생성
    db = create_test_database()
    
    # 테스트 데이터 생성
    create_test_data(db)
    
    # 엑셀 export 테스트
    test_excel_exports(db)
    
    print("\n테스트 완료!")

if __name__ == "__main__":
    main()
