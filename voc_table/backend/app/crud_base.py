# Generic CRUD Base Class
from typing import TypeVar, Generic, Type, Optional, List, Dict, Any
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime

from .db_models import Base
from .logging_conf import log_user_creation, log_user_update

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)


class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    """Generic CRUD Base Class for common database operations"""

    def __init__(self, model: Type[ModelType]):
        """
        CRUD object with default methods to Create, Read, Update, Delete (CRUD).

        **Parameters**
        * `model`: A SQLAlchemy model class
        """
        self.model = model

    def get(self, db: Session, id: int) -> Optional[ModelType]:
        """Get a single record by ID"""
        return db.query(self.model).filter(self.model.id == id).first()

    def get_multi(
        self,
        db: Session,
        *,
        skip: int = 0,
        limit: int = 100
    ) -> List[ModelType]:
        """Get multiple records with pagination"""
        return db.query(self.model).offset(skip).limit(limit).all()

    def create(
        self,
        db: Session,
        *,
        obj_in: CreateSchemaType,
        user_id: int,
        ip: Optional[str] = None
    ) -> ModelType:
        """Create a new record"""
        # Pydantic 모델을 딕셔너리로 변환
        obj_in_data = obj_in.dict()

        # 타임스탬프 추가
        if hasattr(self.model, 'created_at'):
            obj_in_data['created_at'] = datetime.utcnow()
        if hasattr(self.model, 'updated_at'):
            obj_in_data['updated_at'] = datetime.utcnow()

        # SQLAlchemy 모델 인스턴스 생성
        db_obj = self.model(**obj_in_data)

        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)

        # 감사 로그 (선택적)
        self._create_audit_log(db, user_id, "create", db_obj.id, None, obj_in_data, ip)

        return db_obj

    def update(
        self,
        db: Session,
        *,
        db_obj: ModelType,
        obj_in: UpdateSchemaType,
        user_id: int,
        ip: Optional[str] = None
    ) -> ModelType:
        """Update an existing record"""
        # 변경 전 데이터 저장
        before_data = self._get_current_data(db_obj)

        # Pydantic 모델을 딕셔너리로 변환 (None 값 제외)
        update_data = obj_in.dict(exclude_unset=True)

        # 필드별 업데이트
        for field, value in update_data.items():
            setattr(db_obj, field, value)

        # 수정 시간 업데이트
        if hasattr(db_obj, 'updated_at'):
            db_obj.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(db_obj)

        # 감사 로그
        self._create_audit_log(db, user_id, "update", db_obj.id, before_data, update_data, ip)

        return db_obj

    def delete(
        self,
        db: Session,
        *,
        id: int,
        user_id: int,
        ip: Optional[str] = None,
        soft_delete: bool = True
    ) -> bool:
        """Delete a record (soft delete by default)"""
        db_obj = self.get(db, id=id)
        if not db_obj:
            return False

        if soft_delete and hasattr(db_obj, 'deleted_at'):
            # Soft delete
            db_obj.deleted_at = datetime.utcnow()
            if hasattr(db_obj, 'updated_at'):
                db_obj.updated_at = datetime.utcnow()
            db.commit()
        else:
            # Hard delete
            before_data = self._get_current_data(db_obj)
            db.delete(db_obj)
            db.commit()

            # 감사 로그
            self._create_audit_log(db, user_id, "delete", id, before_data, {"deleted": True}, ip)

        return True

    def _get_current_data(self, db_obj: ModelType) -> Dict[str, Any]:
        """Get current data from database object for audit log"""
        # 간단한 필드만 추출 (관계는 제외)
        data = {}
        for column in self.model.__table__.columns:
            value = getattr(db_obj, column.name)
            # datetime을 문자열로 변환
            if isinstance(value, datetime):
                value = value.isoformat()
            data[column.name] = value
        return data

    def _create_audit_log(
        self,
        db: Session,
        actor_user_id: int,
        action: str,
        row_id: int,
        before_json: Optional[Dict] = None,
        after_json: Optional[Dict] = None,
        ip: Optional[str] = None
    ):
        """Create audit log entry"""
        from .db_models import AuditLog

        audit_log = AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            table_name=self.model.__tablename__,
            row_id=row_id,
            before_json=before_json,
            after_json=after_json,
            ip=ip,
            created_at=datetime.utcnow()
        )

        db.add(audit_log)
        db.commit()
