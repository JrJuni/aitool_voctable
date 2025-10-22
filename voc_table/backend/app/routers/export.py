# Export 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import os

from .. import schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level
from .. import excel_io

router = APIRouter()


@router.get("/voc")
async def export_voc_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    VOC 테이블만 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_voc_to_excel(db)
        return {
            "success": True,
            "message": "VOC Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"VOC export failed: {str(e)}")


@router.get("/full")
async def export_full_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    Users 제외한 모든 테이블을 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_full_tables_to_excel(db)
        return {
            "success": True,
            "message": "Full Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full export failed: {str(e)}")


@router.get("/all")
async def export_all_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    모든 테이블을 엑셀로 내보내기
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_all_tables_to_excel(db)
        return {
            "success": True,
            "message": "All tables Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"All export failed: {str(e)}")


@router.get("/biz")
async def export_biz_template_excel(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    VOC와 Projects 2개 시트가 있는 비즈니스 템플릿 엑셀 파일 생성
    나중에 input 템플릿으로 사용할 예정
    - 권한: Level 1 이상
    """
    try:
        filepath = excel_io.export_biz_template_to_excel(db)
        return {
            "success": True,
            "message": "Business template Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Business template export failed: {str(e)}")


@router.get("/table/{table_name}")
async def export_table_excel(
    table_name: str,
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    특정 테이블만 엑셀로 내보내기
    - 권한: Level 1 이상
    - table_name: users, companies, contacts, projects, vocs, audit_logs
    """
    try:
        filepath = excel_io.export_table_to_excel(db, table_name)
        return {
            "success": True,
            "message": f"Table {table_name} Excel export completed",
            "filepath": filepath,
            "filename": os.path.basename(filepath)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Table export failed: {str(e)}")


@router.get("/info")
async def get_export_info(
    current_user: schemas.User = Depends(require_auth_level(1)),
    db: Session = Depends(get_db)
):
    """
    모든 테이블의 기본 정보 반환 (레코드 수 등)
    - 권한: Level 1 이상
    """
    try:
        info = excel_io.get_table_info(db)
        return {
            "success": True,
            "tables": info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get table info: {str(e)}")
