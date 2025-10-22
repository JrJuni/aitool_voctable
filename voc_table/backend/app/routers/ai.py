# AI 관련 라우터
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime

from .. import crud, schemas
from ..db import get_db
from ..dependencies import get_current_user, require_auth_level

router = APIRouter()


@router.post("/analyze/voc")
async def analyze_voc_text(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트를 분석하여 VOC 형태로 구조화
    - 회의록, 메일, 녹취록 등을 VOC 데이터로 변환
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from ..ai_utils import analyze_voc_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다. 관리자에게 문의하세요."
            )

        # 컨텍스트 정보 구성
        context = {
            "user_id": current_user.id,
            "username": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request.context:
            context.update(request.context)

        # AI 분석 실행
        result = analyze_voc_content(request.text, context)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다. llama-cpp-python이 설치되어 있는지 확인하세요."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")


@router.post("/analyze/project")
async def analyze_project_text(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트를 분석하여 프로젝트 형태로 구조화
    - 프로젝트 제안서, 기술 문서 등을 프로젝트 데이터로 변환
    - 권한: Level 2 이상
    """
    require_auth_level(current_user, 2)

    try:
        from ..ai_utils import analyze_project_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        context = {
            "user_id": current_user.id,
            "username": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request.context:
            context.update(request.context)

        result = analyze_project_content(request.text, context)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")


@router.post("/analyze/mixed")
async def analyze_mixed_content(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트 유형을 자동 판별하고 적절한 분석 수행
    - VOC, 프로젝트, 연락처 정보를 자동으로 구분하여 분석
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from ..ai_utils import analyze_mixed_content, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        result = analyze_mixed_content(request.text)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="AI 분석 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "analysis": result,
            "analyzed_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 분석 오류: {str(e)}")


@router.post("/extract/contact")
async def extract_contact_info(
    request: schemas.AITextAnalysisRequest,
    current_user: schemas.User = Depends(get_current_user)
):
    """
    텍스트에서 연락처 정보 추출
    - 이메일 서명, 명함, 자기소개에서 연락처 정보 추출
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from ..ai_utils import extract_contact_info, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        result = extract_contact_info(request.text)

        if not result:
            raise HTTPException(
                status_code=500,
                detail="연락처 정보 추출 중 오류가 발생했습니다."
            )

        return {
            "success": True,
            "contact_info": result,
            "extracted_at": datetime.utcnow(),
            "analyzer": "llama.cpp"
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"연락처 추출 오류: {str(e)}")


@router.post("/voc/{voc_id}/regenerate-summary")
async def regenerate_voc_summary(
    voc_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    기존 VOC의 AI 요약을 다시 생성
    - 권한: Level 2 이상
    """
    require_auth_level(current_user, 2)

    # VOC 조회
    voc = crud.get_voc(db, voc_id=voc_id)
    if not voc:
        raise HTTPException(status_code=404, detail="VOC를 찾을 수 없습니다")

    try:
        from ..ai_utils import generate_ai_summary, llm

        if llm is None:
            raise HTTPException(
                status_code=503,
                detail="AI 서비스가 활성화되지 않았습니다."
            )

        # VOC 데이터로 요약 생성
        voc_data = {
            "content": voc.content,
            "action_item": voc.action_item,
            "status": voc.status,
            "priority": voc.priority
        }

        new_summary = generate_ai_summary(voc_data)

        # 업데이트
        updated_voc = crud.update_voc(
            db, voc_id=voc_id,
            voc=schemas.VOCUpdate(ai_summary=new_summary)
        )

        return {
            "success": True,
            "voc_id": voc_id,
            "new_summary": new_summary,
            "updated_at": updated_voc.updated_at
        }

    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="AI 유틸리티를 불러올 수 없습니다."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"요약 생성 오류: {str(e)}")


@router.get("/status")
async def get_ai_status(
    current_user: schemas.User = Depends(get_current_user)
):
    """
    AI 서비스 상태 조회
    - 권한: Level 1 이상
    """
    require_auth_level(current_user, 1)

    try:
        from ..ai_utils import llm
        from ..config import settings

        return {
            "ai_enabled": settings.AI_ENABLED,
            "model_path": settings.MODEL_PATH,
            "model_loaded": llm is not None,
            "max_tokens": settings.AI_MAX_TOKENS,
            "temperature": settings.AI_TEMPERATURE,
            "context_length": settings.AI_CONTEXT_LENGTH,
            "status": "active" if llm is not None else "inactive"
        }

    except ImportError:
        return {
            "ai_enabled": False,
            "error": "AI 유틸리티를 불러올 수 없습니다.",
            "status": "unavailable"
        }
