# SQLAlchemy 모델
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, Date, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    auth_level = Column(Integer, default=0)  # 0: 승인대기, 1-5: 권한레벨
    is_active = Column(Boolean, default=True)
    department = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)  # 회사명 검색용 기존 인덱스
    domain = Column(String(255), nullable=True)
    revenue = Column(String(100), nullable=True)
    employee = Column(Integer, nullable=True, index=True)  # 직원 수 범위 검색용 인덱스
    nation = Column(String(100), nullable=True, index=True)  # 국가별 필터용 인덱스
    created_at = Column(DateTime, default=func.now(), index=True)  # 생성일 정렬용 인덱스
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), index=True)  # 수정일 정렬용 인덱스
    
    # 관계 설정
    contacts = relationship("Contact", back_populates="company")
    projects = relationship("Project", back_populates="company")
    vocs = relationship("VOC", back_populates="company")

class Contact(Base):
    __tablename__ = "contacts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    title = Column(String(100), nullable=True)
    email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    note = Column(Text, nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # 관계 설정
    company = relationship("Company", back_populates="contacts")
    vocs = relationship("VOC", back_populates="contact")

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)  # 프로젝트명 검색용 인덱스
    field = Column(String(100), nullable=True, index=True)  # 분야별 필터용 인덱스
    target_app = Column(String(255), nullable=True)
    ai_model = Column(String(255), nullable=True)
    perf = Column(String(100), nullable=True)
    power = Column(String(100), nullable=True)
    size = Column(String(100), nullable=True)
    price = Column(String(100), nullable=True)
    requirements = Column(Text, nullable=True)
    competitors = Column(Text, nullable=True)
    result = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)  # 회사별 프로젝트 필터용 인덱스
    created_at = Column(DateTime, default=func.now(), index=True)  # 생성일 정렬용 인덱스
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), index=True)  # 수정일 정렬용 인덱스
    
    # 관계 설정
    company = relationship("Company", back_populates="projects")
    vocs = relationship("VOC", back_populates="project")

class VOC(Base):
    __tablename__ = "vocs"

    id = Column(Integer, primary_key=True, index=True)
    date = Column(Date, nullable=False, index=True)  # 날짜 검색용 인덱스
    content = Column(Text, nullable=False)
    action_item = Column(Text, nullable=True)
    due_date = Column(Date, nullable=True, index=True)  # 마감일 검색용 인덱스
    status = Column(String(50), nullable=False, default="in_progress", index=True)  # 상태 필터용 인덱스
    priority = Column(String(50), nullable=False, default="medium", index=True)  # 우선순위 필터용 인덱스
    assignee_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)  # 담당자 필터용 인덱스
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False, index=True)  # 회사 필터용 인덱스
    contact_id = Column(Integer, ForeignKey("contacts.id"), nullable=True, index=True)  # 연락처 필터용 인덱스
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True, index=True)  # 프로젝트 필터용 인덱스
    ai_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), index=True)  # 생성일 정렬용 인덱스
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), index=True)  # 수정일 정렬용 인덱스
    deleted_at = Column(DateTime, nullable=True, index=True)  # 소프트 삭제 필터용 인덱스
    
    # 관계 설정
    company = relationship("Company", back_populates="vocs")
    contact = relationship("Contact", back_populates="vocs")
    project = relationship("Project", back_populates="vocs")
    assignee = relationship("User")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)
    table_name = Column(String(50), nullable=False)
    row_id = Column(Integer, nullable=False)
    before_json = Column(JSON)
    after_json = Column(JSON)
    ip = Column(String(45))
    ua = Column(Text)
    created_at = Column(DateTime, default=func.now())