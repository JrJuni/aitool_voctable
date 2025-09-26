# DB 접근 함수(단계적)
from sqlalchemy.orm import Session
from sqlalchemy import and_
from passlib.context import CryptContext
from datetime import datetime
from typing import Optional, List
from .db_models import User, AuditLog, Company, Contact, Project, VOC
from .schemas import UserCreate, UserUpdate, CompanyCreate, CompanyUpdate, ContactCreate, ContactUpdate, ProjectCreate, ProjectUpdate, VOCCreate, VOCUpdate
from .logging_conf import log_user_creation, log_user_update

# 비밀번호 해싱 컨텍스트
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """비밀번호 검증"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """비밀번호 해싱"""
    return pwd_context.hash(password)

# 사용자 관련 CRUD 함수들
def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """ID로 사용자 조회"""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """이메일로 사용자 조회"""
    return db.query(User).filter(User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """사용자명으로 사용자 조회"""
    return db.query(User).filter(User.username == username).first()

def get_user_by_email_and_username(db: Session, email: str, username: str) -> Optional[User]:
    """이메일과 사용자명으로 사용자 조회"""
    return db.query(User).filter(and_(User.email == email, User.username == username)).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    """사용자 목록 조회 (페이지네이션)"""
    return db.query(User).offset(skip).limit(limit).all()

def get_users_by_auth_level(db: Session, auth_level: int, skip: int = 0, limit: int = 100) -> List[User]:
    """특정 권한 레벨의 사용자 목록 조회"""
    return db.query(User).filter(User.auth_level == auth_level).offset(skip).limit(limit).all()

def create_user(db: Session, user: UserCreate, ip: Optional[str] = None) -> User:
    """사용자 생성"""
    # 비밀번호 해싱
    hashed_password = get_password_hash(user.password)
    
    # 사용자 객체 생성
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        auth_level=user.auth_level,
        is_active=user.is_active,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    # DB에 저장
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # 로그 기록
    log_user_creation(db_user.id, db_user.email, db_user.auth_level, ip)
    
    return db_user

def update_user(db: Session, user_id: int, user_update: UserUpdate, ip: Optional[str] = None) -> Optional[User]:
    """사용자 정보 수정"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return None
    
    # 변경 전 데이터 저장 (감사 로그용)
    updated_fields = {}
    
    # 필드별 업데이트
    if user_update.email is not None:
        updated_fields['email'] = f"{db_user.email} -> {user_update.email}"
        db_user.email = user_update.email
    
    if user_update.username is not None:
        updated_fields['username'] = f"{db_user.username} -> {user_update.username}"
        db_user.username = user_update.username
    
    if user_update.auth_level is not None:
        updated_fields['auth_level'] = f"{db_user.auth_level} -> {user_update.auth_level}"
        db_user.auth_level = user_update.auth_level
    
    if user_update.is_active is not None:
        updated_fields['is_active'] = f"{db_user.is_active} -> {user_update.is_active}"
        db_user.is_active = user_update.is_active
    
    if user_update.password is not None:
        updated_fields['password'] = "*** -> ***"  # 보안상 비밀번호는 마스킹
        db_user.hashed_password = get_password_hash(user_update.password)
    
    # 수정 시간 업데이트
    db_user.updated_at = datetime.utcnow()
    
    # DB에 저장
    db.commit()
    db.refresh(db_user)
    
    # 로그 기록
    if updated_fields:
        log_user_update(db_user.id, db_user.email, updated_fields, ip)
    
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """사용자 인증 (이메일/비밀번호 검증)"""
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    if user.auth_level == 0:
        return None  # 승인 대기 상태(레벨 0)는 로그인 불가
    return user

def check_password_reset_needed(db: Session, email: str, password: str) -> bool:
    """비밀번호가 0000인지 확인"""
    user = get_user_by_email(db, email)
    if not user:
        return False
    return verify_password("0000", user.hashed_password) and password == "0000"

def reset_password_to_default(db: Session, user_id: int, actor_user_id: int, ip: Optional[str] = None) -> bool:
    """비밀번호를 0000으로 초기화"""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    # 비밀번호를 0000으로 초기화
    user.hashed_password = get_password_hash("0000")
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=actor_user_id,
        action="password_reset",
        table_name="users",
        row_id=user.id,
        after_json={"action": "password_reset_to_0000"},
        ip=ip
    )
    
    return True

def update_password(db: Session, user_id: int, new_password: str, ip: Optional[str] = None) -> bool:
    """사용자 비밀번호 업데이트"""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    user.hashed_password = get_password_hash(new_password)
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="password_update",
        table_name="users",
        row_id=user.id,
        after_json={"action": "password_updated"},
        ip=ip
    )
    
    return True

def get_users_with_reset_permission(db: Session, user_auth_level: int) -> List[User]:
    """비밀번호 초기화 권한이 있는 사용자 목록 조회 (레벨 3-5, 동급 이상)"""
    return db.query(User).filter(
        and_(
            User.auth_level >= 3,
            User.auth_level >= user_auth_level,
            User.is_active == True
        )
    ).all()

def delete_user(db: Session, user_id: int) -> bool:
    """사용자 삭제 (소프트 삭제)"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return False
    
    # 소프트 삭제: is_active를 False로 설정
    db_user.is_active = False
    db_user.updated_at = datetime.utcnow()
    
    db.commit()
    return True

def hard_delete_user(db: Session, user_id: int) -> bool:
    """사용자 완전 삭제 (레벨 5 이상만 가능)"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return False
    
    db.delete(db_user)
    db.commit()
    return True

# 감사 로그 관련 함수들
def create_audit_log(db: Session, actor_user_id: int, action: str, table_name: str, 
                    row_id: int, before_json: Optional[dict] = None, 
                    after_json: Optional[dict] = None, ip: Optional[str] = None, 
                    user_agent: Optional[str] = None) -> AuditLog:
    """감사 로그 생성"""
    audit_log = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        table_name=table_name,
        row_id=row_id,
        before_json=before_json,
        after_json=after_json,
        ip=ip,
        ua=user_agent,
        created_at=datetime.utcnow()
    )
    
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    
    return audit_log

def get_audit_logs(db: Session, skip: int = 0, limit: int = 100, 
                  table_name: Optional[str] = None, 
                  actor_user_id: Optional[int] = None) -> List[AuditLog]:
    """감사 로그 조회"""
    query = db.query(AuditLog)
    
    if table_name:
        query = query.filter(AuditLog.table_name == table_name)
    
    if actor_user_id:
        query = query.filter(AuditLog.actor_user_id == actor_user_id)
    
    return query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()

# =============================================================================
# VOC 관련 CRUD 함수들
# =============================================================================

def get_vocs(db: Session, skip: int = 0, limit: int = 100) -> List[VOC]:
    """VOC 목록 조회"""
    return db.query(VOC).options(
        db.joinedload(VOC.company),
        db.joinedload(VOC.contact),
        db.joinedload(VOC.project),
        db.joinedload(VOC.assignee)
    ).filter(VOC.deleted_at.is_(None)).offset(skip).limit(limit).all()

def get_voc(db: Session, voc_id: int) -> Optional[VOC]:
    """VOC 상세 조회"""
    return db.query(VOC).options(
        db.joinedload(VOC.company),
        db.joinedload(VOC.contact),
        db.joinedload(VOC.project),
        db.joinedload(VOC.assignee)
    ).filter(VOC.id == voc_id, VOC.deleted_at.is_(None)).first()

def create_voc(db: Session, voc: VOCCreate, user_id: int, ip: Optional[str] = None) -> VOC:
    """VOC 생성"""
    db_voc = VOC(
        date=voc.date,
        content=voc.content,
        action_item=voc.action_item,
        due_date=voc.due_date,
        status=voc.status,
        priority=voc.priority,
        assignee_user_id=voc.assignee_user_id,
        company_id=voc.company_id,
        contact_id=voc.contact_id,
        project_id=voc.project_id,
        ai_summary=voc.ai_summary,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(db_voc)
    db.commit()
    db.refresh(db_voc)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="create",
        table_name="vocs",
        row_id=db_voc.id,
        after_json=voc.dict(),
        ip=ip
    )
    
    return db_voc

def update_voc(db: Session, voc_id: int, voc_update: VOCUpdate, user_id: int, ip: Optional[str] = None) -> Optional[VOC]:
    """VOC 수정"""
    db_voc = get_voc(db, voc_id)
    if not db_voc:
        return None
    
    # 변경 전 데이터 저장
    before_data = {
        "date": str(db_voc.date),
        "content": db_voc.content,
        "action_item": db_voc.action_item,
        "due_date": str(db_voc.due_date) if db_voc.due_date else None,
        "status": db_voc.status,
        "priority": db_voc.priority,
        "assignee_user_id": db_voc.assignee_user_id,
        "company_id": db_voc.company_id,
        "contact_id": db_voc.contact_id,
        "project_id": db_voc.project_id,
        "ai_summary": db_voc.ai_summary
    }
    
    # 필드별 업데이트
    update_data = voc_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_voc, field, value)
    
    db_voc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_voc)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="update",
        table_name="vocs",
        row_id=voc_id,
        before_json=before_data,
        after_json=update_data,
        ip=ip
    )
    
    return db_voc

def delete_voc(db: Session, voc_id: int, user_id: int, ip: Optional[str] = None) -> bool:
    """VOC 삭제 (소프트 삭제)"""
    db_voc = get_voc(db, voc_id)
    if not db_voc:
        return False
    
    # 소프트 삭제
    db_voc.deleted_at = datetime.utcnow()
    db_voc.updated_at = datetime.utcnow()
    db.commit()
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="delete",
        table_name="vocs",
        row_id=voc_id,
        before_json={"deleted_at": None},
        after_json={"deleted_at": str(datetime.utcnow())},
        ip=ip
    )
    
    return True

# =============================================================================
# Company 관련 CRUD 함수들
# =============================================================================

def get_companies(db: Session, skip: int = 0, limit: int = 100) -> List[Company]:
    """회사 목록 조회"""
    return db.query(Company).offset(skip).limit(limit).all()

def get_company(db: Session, company_id: int) -> Optional[Company]:
    """회사 상세 조회"""
    return db.query(Company).filter(Company.id == company_id).first()

def create_company(db: Session, company: CompanyCreate, user_id: int, ip: Optional[str] = None) -> Company:
    """회사 생성"""
    db_company = Company(
        name=company.name,
        domain=company.domain,
        revenue=company.revenue,
        employee=company.employee,
        nation=company.nation,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(db_company)
    db.commit()
    db.refresh(db_company)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="create",
        table_name="companies",
        row_id=db_company.id,
        after_json=company.dict(),
        ip=ip
    )
    
    return db_company

def update_company(db: Session, company_id: int, company_update: CompanyUpdate, user_id: int, ip: Optional[str] = None) -> Optional[Company]:
    """회사 수정"""
    db_company = get_company(db, company_id)
    if not db_company:
        return None
    
    # 변경 전 데이터 저장
    before_data = {
        "name": db_company.name,
        "domain": db_company.domain,
        "revenue": db_company.revenue,
        "employee": db_company.employee,
        "nation": db_company.nation
    }
    
    # 필드별 업데이트
    update_data = company_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_company, field, value)
    
    db_company.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_company)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="update",
        table_name="companies",
        row_id=company_id,
        before_json=before_data,
        after_json=update_data,
        ip=ip
    )
    
    return db_company

def delete_company(db: Session, company_id: int, user_id: int, ip: Optional[str] = None) -> bool:
    """회사 삭제"""
    db_company = get_company(db, company_id)
    if not db_company:
        return False
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="delete",
        table_name="companies",
        row_id=company_id,
        before_json={"name": db_company.name},
        after_json={"deleted": True},
        ip=ip
    )
    
    db.delete(db_company)
    db.commit()
    return True

# =============================================================================
# Contact 관련 CRUD 함수들
# =============================================================================

def get_contacts(db: Session, skip: int = 0, limit: int = 100) -> List[Contact]:
    """연락처 목록 조회"""
    return db.query(Contact).offset(skip).limit(limit).all()

def get_contact(db: Session, contact_id: int) -> Optional[Contact]:
    """연락처 상세 조회"""
    return db.query(Contact).filter(Contact.id == contact_id).first()

def create_contact(db: Session, contact: ContactCreate, user_id: int, ip: Optional[str] = None) -> Contact:
    """연락처 생성"""
    db_contact = Contact(
        name=contact.name,
        title=contact.title,
        email=contact.email,
        phone=contact.phone,
        note=contact.note,
        company_id=contact.company_id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="create",
        table_name="contacts",
        row_id=db_contact.id,
        after_json=contact.dict(),
        ip=ip
    )
    
    return db_contact

def update_contact(db: Session, contact_id: int, contact_update: ContactUpdate, user_id: int, ip: Optional[str] = None) -> Optional[Contact]:
    """연락처 수정"""
    db_contact = get_contact(db, contact_id)
    if not db_contact:
        return None
    
    # 변경 전 데이터 저장
    before_data = {
        "name": db_contact.name,
        "title": db_contact.title,
        "email": db_contact.email,
        "phone": db_contact.phone,
        "note": db_contact.note,
        "company_id": db_contact.company_id
    }
    
    # 필드별 업데이트
    update_data = contact_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_contact, field, value)
    
    db_contact.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_contact)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="update",
        table_name="contacts",
        row_id=contact_id,
        before_json=before_data,
        after_json=update_data,
        ip=ip
    )
    
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int, ip: Optional[str] = None) -> bool:
    """연락처 삭제"""
    db_contact = get_contact(db, contact_id)
    if not db_contact:
        return False
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="delete",
        table_name="contacts",
        row_id=contact_id,
        before_json={"name": db_contact.name},
        after_json={"deleted": True},
        ip=ip
    )
    
    db.delete(db_contact)
    db.commit()
    return True

# =============================================================================
# Project 관련 CRUD 함수들
# =============================================================================

def get_projects(db: Session, skip: int = 0, limit: int = 100) -> List[Project]:
    """프로젝트 목록 조회"""
    return db.query(Project).offset(skip).limit(limit).all()

def get_project(db: Session, project_id: int) -> Optional[Project]:
    """프로젝트 상세 조회"""
    return db.query(Project).filter(Project.id == project_id).first()

def create_project(db: Session, project: ProjectCreate, user_id: int, ip: Optional[str] = None) -> Project:
    """프로젝트 생성"""
    db_project = Project(
        name=project.name,
        field=project.field,
        target_app=project.target_app,
        ai_model=project.ai_model,
        perf=project.perf,
        power=project.power,
        form_factor=project.form_factor,
        memory=project.memory,
        price=project.price,
        requirements=project.requirements,
        competitors=project.competitors,
        result=project.result,
        root_cause=project.root_cause,
        company_id=project.company_id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="create",
        table_name="projects",
        row_id=db_project.id,
        after_json=project.dict(),
        ip=ip
    )
    
    return db_project

def update_project(db: Session, project_id: int, project_update: ProjectUpdate, user_id: int, ip: Optional[str] = None) -> Optional[Project]:
    """프로젝트 수정"""
    db_project = get_project(db, project_id)
    if not db_project:
        return None
    
    # 변경 전 데이터 저장
    before_data = {
        "name": db_project.name,
        "field": db_project.field,
        "target_app": db_project.target_app,
        "ai_model": db_project.ai_model,
        "perf": db_project.perf,
        "power": db_project.power,
        "form_factor": db_project.form_factor,
        "memory": db_project.memory,
        "price": db_project.price,
        "requirements": db_project.requirements,
        "competitors": db_project.competitors,
        "result": db_project.result,
        "root_cause": db_project.root_cause,
        "company_id": db_project.company_id
    }
    
    # 필드별 업데이트
    update_data = project_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_project, field, value)
    
    db_project.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_project)
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="update",
        table_name="projects",
        row_id=project_id,
        before_json=before_data,
        after_json=update_data,
        ip=ip
    )
    
    return db_project

def delete_project(db: Session, project_id: int, user_id: int, ip: Optional[str] = None) -> bool:
    """프로젝트 삭제"""
    db_project = get_project(db, project_id)
    if not db_project:
        return False
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="delete",
        table_name="projects",
        row_id=project_id,
        before_json={"name": db_project.name},
        after_json={"deleted": True},
        ip=ip
    )
    
    db.delete(db_project)
    db.commit()
    return True


# =============================================================================
# 대량 업데이트 함수들
# =============================================================================

def bulk_update_vocs(db: Session, voc_updates: List[VOCUpdate], user_id: int, ip: Optional[str] = None) -> dict:
    """대량 VOC 업데이트"""
    success_count = 0
    error_count = 0
    errors = []
    
    for i, voc_update in enumerate(voc_updates):
        try:
            if hasattr(voc_update, 'id') and voc_update.id:
                # 기존 VOC 업데이트
                db_voc = get_voc(db, voc_id=voc_update.id)
                if db_voc:
                    update_voc(db=db, voc_id=voc_update.id, voc_update=voc_update, user_id=user_id, ip=ip)
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"VOC ID {voc_update.id} not found")
            else:
                error_count += 1
                errors.append(f"VOC update at index {i} missing ID")
        except Exception as e:
            error_count += 1
            errors.append(f"Error updating VOC at index {i}: {str(e)}")
    
    return {
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }


def bulk_update_companies(db: Session, company_updates: List[CompanyUpdate], user_id: int, ip: Optional[str] = None) -> dict:
    """대량 Company 업데이트"""
    success_count = 0
    error_count = 0
    errors = []
    
    for i, company_update in enumerate(company_updates):
        try:
            if hasattr(company_update, 'id') and company_update.id:
                # 기존 Company 업데이트
                db_company = get_company(db, company_id=company_update.id)
                if db_company:
                    update_company(db=db, company_id=company_update.id, company_update=company_update, user_id=user_id, ip=ip)
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"Company ID {company_update.id} not found")
            else:
                error_count += 1
                errors.append(f"Company update at index {i} missing ID")
        except Exception as e:
            error_count += 1
            errors.append(f"Error updating Company at index {i}: {str(e)}")
    
    return {
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }


def bulk_update_contacts(db: Session, contact_updates: List[ContactUpdate], user_id: int, ip: Optional[str] = None) -> dict:
    """대량 Contact 업데이트"""
    success_count = 0
    error_count = 0
    errors = []
    
    for i, contact_update in enumerate(contact_updates):
        try:
            if hasattr(contact_update, 'id') and contact_update.id:
                # 기존 Contact 업데이트
                db_contact = get_contact(db, contact_id=contact_update.id)
                if db_contact:
                    update_contact(db=db, contact_id=contact_update.id, contact_update=contact_update, user_id=user_id, ip=ip)
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"Contact ID {contact_update.id} not found")
            else:
                error_count += 1
                errors.append(f"Contact update at index {i} missing ID")
        except Exception as e:
            error_count += 1
            errors.append(f"Error updating Contact at index {i}: {str(e)}")
    
    return {
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }


def bulk_update_projects(db: Session, project_updates: List[ProjectUpdate], user_id: int, ip: Optional[str] = None) -> dict:
    """대량 Project 업데이트"""
    success_count = 0
    error_count = 0
    errors = []
    
    for i, project_update in enumerate(project_updates):
        try:
            if hasattr(project_update, 'id') and project_update.id:
                # 기존 Project 업데이트
                db_project = get_project(db, project_id=project_update.id)
                if db_project:
                    update_project(db=db, project_id=project_update.id, project_update=project_update, user_id=user_id, ip=ip)
                    success_count += 1
                else:
                    error_count += 1
                    errors.append(f"Project ID {project_update.id} not found")
            else:
                error_count += 1
                errors.append(f"Project update at index {i} missing ID")
        except Exception as e:
            error_count += 1
            errors.append(f"Error updating Project at index {i}: {str(e)}")
    
    return {
        "success_count": success_count,
        "error_count": error_count,
        "errors": errors
    }