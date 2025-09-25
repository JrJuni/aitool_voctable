# VOC 테이블 검색/필터 시스템
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, asc, func, Date, cast
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
from enum import Enum

from .db_models import VOC, Company, Contact, Project, User


class SortOrder(str, Enum):
    """정렬 순서"""
    ASC = "asc"
    DESC = "desc"


class VOCStatus(str, Enum):
    """VOC 상태"""
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PENDING = "pending"


class VOCPriority(str, Enum):
    """VOC 우선순위"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class VOCFilterParams(BaseModel):
    """VOC 필터링 파라미터"""
    # 페이지네이션
    skip: int = Field(0, ge=0, description="건너뛸 레코드 수")
    limit: int = Field(100, ge=1, le=1000, description="조회할 레코드 수")

    # 날짜 필터
    from_date: Optional[date] = Field(None, description="시작 날짜 (YYYY-MM-DD)")
    to_date: Optional[date] = Field(None, description="종료 날짜 (YYYY-MM-DD)")
    created_from: Optional[datetime] = Field(None, description="생성일 시작")
    created_to: Optional[datetime] = Field(None, description="생성일 종료")

    # 기본 필터
    company_id: Optional[int] = Field(None, description="회사 ID")
    contact_id: Optional[int] = Field(None, description="담당자 ID")
    project_id: Optional[int] = Field(None, description="프로젝트 ID")
    assignee_user_id: Optional[int] = Field(None, description="담당 사용자 ID")

    # 상태/우선순위 필터
    status: Optional[VOCStatus] = Field(None, description="VOC 상태")
    priority: Optional[VOCPriority] = Field(None, description="VOC 우선순위")

    # 텍스트 검색
    search_text: Optional[str] = Field(None, min_length=1, max_length=100, description="내용 검색")
    search_company: Optional[str] = Field(None, min_length=1, max_length=50, description="회사명 검색")

    # 정렬
    sort_by: str = Field("created_at", description="정렬 기준")
    sort_order: SortOrder = Field(SortOrder.DESC, description="정렬 순서")

    # 삭제된 항목 포함 여부
    include_deleted: bool = Field(False, description="삭제된 VOC 포함 여부")

    @validator('from_date', 'to_date')
    def validate_dates(cls, v, values):
        """날짜 유효성 검증"""
        if v and 'from_date' in values and values['from_date']:
            if v < values['from_date']:
                raise ValueError('to_date must be greater than or equal to from_date')
        return v

    @validator('sort_by')
    def validate_sort_by(cls, v):
        """정렬 기준 유효성 검증"""
        allowed_fields = [
            'id', 'date', 'created_at', 'updated_at', 'due_date',
            'status', 'priority', 'company_id', 'assignee_user_id'
        ]
        if v not in allowed_fields:
            raise ValueError(f'sort_by must be one of: {allowed_fields}')
        return v


class CompanyFilterParams(BaseModel):
    """회사 필터링 파라미터"""
    skip: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    search_name: Optional[str] = Field(None, min_length=1, max_length=100)
    nation: Optional[str] = Field(None, description="국가")
    min_employee: Optional[int] = Field(None, ge=0, description="최소 직원 수")
    max_employee: Optional[int] = Field(None, ge=0, description="최대 직원 수")
    sort_by: str = Field("created_at", description="정렬 기준")
    sort_order: SortOrder = Field(SortOrder.DESC, description="정렬 순서")


class ProjectFilterParams(BaseModel):
    """프로젝트 필터링 파라미터"""
    skip: int = Field(0, ge=0)
    limit: int = Field(100, ge=1, le=1000)
    company_id: Optional[int] = Field(None, description="회사 ID")
    search_name: Optional[str] = Field(None, min_length=1, max_length=100)
    field: Optional[str] = Field(None, description="분야")
    sort_by: str = Field("created_at", description="정렬 기준")
    sort_order: SortOrder = Field(SortOrder.DESC, description="정렬 순서")


class VOCFilterResult(BaseModel):
    """VOC 필터링 결과"""
    items: List[Dict[str, Any]]
    total: int
    skip: int
    limit: int
    has_more: bool


def build_voc_query(db: Session, filters: VOCFilterParams) -> tuple:
    """
    VOC 검색 쿼리 빌더

    Args:
        db: 데이터베이스 세션
        filters: 필터 파라미터

    Returns:
        tuple: (query, count_query)
    """
    # 기본 쿼리 - 관련 테이블 조인
    query = db.query(VOC).options(
        joinedload(VOC.company),
        joinedload(VOC.contact),
        joinedload(VOC.project),
        joinedload(VOC.assignee)
    )

    # 카운트용 쿼리 (조인 없이)
    count_query = db.query(func.count(VOC.id))

    # 공통 WHERE 조건 적용
    conditions = []

    # 삭제된 항목 필터링
    if not filters.include_deleted:
        conditions.append(VOC.deleted_at.is_(None))

    # 날짜 범위 필터
    if filters.from_date:
        conditions.append(VOC.date >= filters.from_date)
    if filters.to_date:
        conditions.append(VOC.date <= filters.to_date)

    # 생성일 범위 필터
    if filters.created_from:
        conditions.append(VOC.created_at >= filters.created_from)
    if filters.created_to:
        conditions.append(VOC.created_at <= filters.created_to)

    # 기본 필터
    if filters.company_id:
        conditions.append(VOC.company_id == filters.company_id)
    if filters.contact_id:
        conditions.append(VOC.contact_id == filters.contact_id)
    if filters.project_id:
        conditions.append(VOC.project_id == filters.project_id)
    if filters.assignee_user_id:
        conditions.append(VOC.assignee_user_id == filters.assignee_user_id)

    # 상태/우선순위 필터
    if filters.status:
        conditions.append(VOC.status == filters.status.value)
    if filters.priority:
        conditions.append(VOC.priority == filters.priority.value)

    # 텍스트 검색 - 내용 검색
    if filters.search_text:
        search_condition = or_(
            VOC.content.ilike(f'%{filters.search_text}%'),
            VOC.action_item.ilike(f'%{filters.search_text}%'),
            VOC.ai_summary.ilike(f'%{filters.search_text}%')
        )
        conditions.append(search_condition)

    # 회사명 검색 - Company 테이블 조인 필요
    if filters.search_company:
        query = query.join(Company, VOC.company_id == Company.id)
        count_query = count_query.join(Company, VOC.company_id == Company.id)
        conditions.append(Company.name.ilike(f'%{filters.search_company}%'))

    # WHERE 조건 적용
    if conditions:
        query = query.filter(and_(*conditions))
        count_query = count_query.filter(and_(*conditions))

    # 정렬 적용
    sort_column = getattr(VOC, filters.sort_by)
    if filters.sort_order == SortOrder.DESC:
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    return query, count_query


def get_filtered_vocs(db: Session, filters: VOCFilterParams) -> VOCFilterResult:
    """
    필터링된 VOC 목록 조회

    Args:
        db: 데이터베이스 세션
        filters: 필터 파라미터

    Returns:
        VOCFilterResult: 필터링 결과
    """
    # 쿼리 빌드
    query, count_query = build_voc_query(db, filters)

    # 전체 개수 조회
    total = count_query.scalar()

    # 페이지네이션 적용
    items_query = query.offset(filters.skip).limit(filters.limit)
    items = items_query.all()

    # 결과 변환
    result_items = []
    for voc in items:
        item = {
            "id": voc.id,
            "date": voc.date,
            "content": voc.content,
            "action_item": voc.action_item,
            "due_date": voc.due_date,
            "status": voc.status,
            "priority": voc.priority,
            "ai_summary": voc.ai_summary,
            "created_at": voc.created_at,
            "updated_at": voc.updated_at,
            "company": {
                "id": voc.company.id,
                "name": voc.company.name
            } if voc.company else None,
            "contact": {
                "id": voc.contact.id,
                "name": voc.contact.name,
                "title": voc.contact.title
            } if voc.contact else None,
            "project": {
                "id": voc.project.id,
                "name": voc.project.name
            } if voc.project else None,
            "assignee": {
                "id": voc.assignee.id,
                "name": voc.assignee.username,
                "email": voc.assignee.email
            } if voc.assignee else None
        }
        result_items.append(item)

    return VOCFilterResult(
        items=result_items,
        total=total,
        skip=filters.skip,
        limit=filters.limit,
        has_more=(filters.skip + len(result_items)) < total
    )


def build_company_query(db: Session, filters: CompanyFilterParams) -> tuple:
    """회사 검색 쿼리 빌더"""
    query = db.query(Company)
    count_query = db.query(func.count(Company.id))

    conditions = []

    # 회사명 검색
    if filters.search_name:
        conditions.append(Company.name.ilike(f'%{filters.search_name}%'))

    # 국가 필터
    if filters.nation:
        conditions.append(Company.nation == filters.nation)

    # 직원 수 범위
    if filters.min_employee:
        conditions.append(Company.employee >= filters.min_employee)
    if filters.max_employee:
        conditions.append(Company.employee <= filters.max_employee)

    # WHERE 조건 적용
    if conditions:
        query = query.filter(and_(*conditions))
        count_query = count_query.filter(and_(*conditions))

    # 정렬
    sort_column = getattr(Company, filters.sort_by)
    if filters.sort_order == SortOrder.DESC:
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    return query, count_query


def get_filtered_companies(db: Session, filters: CompanyFilterParams) -> Dict[str, Any]:
    """필터링된 회사 목록 조회"""
    query, count_query = build_company_query(db, filters)

    total = count_query.scalar()
    items = query.offset(filters.skip).limit(filters.limit).all()

    return {
        "items": [
            {
                "id": company.id,
                "name": company.name,
                "domain": company.domain,
                "revenue": company.revenue,
                "employee": company.employee,
                "nation": company.nation,
                "created_at": company.created_at,
                "updated_at": company.updated_at
            }
            for company in items
        ],
        "total": total,
        "skip": filters.skip,
        "limit": filters.limit,
        "has_more": (filters.skip + len(items)) < total
    }


def build_project_query(db: Session, filters: ProjectFilterParams) -> tuple:
    """프로젝트 검색 쿼리 빌더"""
    query = db.query(Project).options(joinedload(Project.company))
    count_query = db.query(func.count(Project.id))

    conditions = []

    # 회사 필터
    if filters.company_id:
        conditions.append(Project.company_id == filters.company_id)

    # 프로젝트명 검색
    if filters.search_name:
        conditions.append(Project.name.ilike(f'%{filters.search_name}%'))

    # 분야 필터
    if filters.field:
        conditions.append(Project.field == filters.field)

    # WHERE 조건 적용
    if conditions:
        query = query.filter(and_(*conditions))
        count_query = count_query.filter(and_(*conditions))

    # 정렬
    sort_column = getattr(Project, filters.sort_by)
    if filters.sort_order == SortOrder.DESC:
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))

    return query, count_query


def get_filtered_projects(db: Session, filters: ProjectFilterParams) -> Dict[str, Any]:
    """필터링된 프로젝트 목록 조회"""
    query, count_query = build_project_query(db, filters)

    total = count_query.scalar()
    items = query.offset(filters.skip).limit(filters.limit).all()

    return {
        "items": [
            {
                "id": project.id,
                "name": project.name,
                "field": project.field,
                "target_app": project.target_app,
                "ai_model": project.ai_model,
                "company": {
                    "id": project.company.id,
                    "name": project.company.name
                } if project.company else None,
                "created_at": project.created_at,
                "updated_at": project.updated_at
            }
            for project in items
        ],
        "total": total,
        "skip": filters.skip,
        "limit": filters.limit,
        "has_more": (filters.skip + len(items)) < total
    }


def get_voc_statistics(db: Session, filters: VOCFilterParams) -> Dict[str, Any]:
    """VOC 통계 조회"""
    base_query, _ = build_voc_query(db, filters)

    # 상태별 통계
    status_stats = (
        base_query
        .with_entities(VOC.status, func.count(VOC.id).label('count'))
        .group_by(VOC.status)
        .all()
    )

    # 우선순위별 통계
    priority_stats = (
        base_query
        .with_entities(VOC.priority, func.count(VOC.id).label('count'))
        .group_by(VOC.priority)
        .all()
    )

    # 월별 통계 (최근 12개월)
    monthly_stats = (
        base_query
        .with_entities(
            func.date_format(VOC.created_at, '%Y-%m').label('month'),
            func.count(VOC.id).label('count')
        )
        .group_by(func.date_format(VOC.created_at, '%Y-%m'))
        .order_by(func.date_format(VOC.created_at, '%Y-%m'))
        .limit(12)
        .all()
    )

    return {
        "status_distribution": [
            {"status": status, "count": count}
            for status, count in status_stats
        ],
        "priority_distribution": [
            {"priority": priority, "count": count}
            for priority, count in priority_stats
        ],
        "monthly_trends": [
            {"month": month, "count": count}
            for month, count in monthly_stats
        ]
    }