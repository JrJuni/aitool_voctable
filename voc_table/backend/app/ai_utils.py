# AI 유틸리티 - llama.cpp 기반 VOC/Project 요약 시스템
import json
import os
from datetime import datetime, date
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

from .config import settings

# llama-cpp-python 선택적 임포트
try:
    from llama_cpp import Llama
    LLAMA_CPP_AVAILABLE = True
except ImportError:
    print("경고: llama-cpp-python이 설치되지 않았습니다. AI 기능을 사용하려면 'pip install llama-cpp-python'을 실행하세요.")
    Llama = None
    LLAMA_CPP_AVAILABLE = False

# AI 요약 결과 모델들
class VOCSummary(BaseModel):
    """VOC 요약 결과"""
    content_summary: str
    action_items: List[str]
    priority: str  # low, medium, high, urgent
    status: str    # in_progress, completed, cancelled, pending
    due_date: Optional[str]
    key_points: List[str]
    sentiment: str  # positive, negative, neutral
    entities: Dict[str, Any]  # 추출된 개체 정보

class ProjectSummary(BaseModel):
    """프로젝트 요약 결과"""
    project_name: str
    field: str
    target_app: Optional[str]
    ai_model: Optional[str]
    requirements: str
    competitors: List[str]
    expected_result: str
    root_cause_analysis: str
    technical_specs: Dict[str, str]  # perf, power, size, price 등

class ContactInfo(BaseModel):
    """연락처 정보"""
    name: Optional[str]
    title: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    company: Optional[str]
    department: Optional[str]

# LLM 모델 초기화
llm = None

def initialize_llm():
    """LLM 모델 초기화"""
    global llm

    if not LLAMA_CPP_AVAILABLE:
        print("llama-cpp-python이 설치되지 않아 AI 기능을 사용할 수 없습니다.")
        return False

    try:
        if not settings.AI_ENABLED:
            print("AI 기능이 비활성화되어 있습니다. AI_ENABLED=true로 설정하세요.")
            return False

        # 모델 파일 경로 확인 및 수정
        model_path = settings.MODEL_PATH
        if not os.path.isabs(model_path):
            # 상대 경로인 경우 절대 경로로 변환
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.abspath(os.path.join(current_dir, model_path))

        if os.path.exists(model_path):
            print(f"LLM 모델을 로딩합니다... 경로: {model_path}")
            llm = Llama(
                model_path=model_path,
                n_ctx=settings.AI_CONTEXT_LENGTH,
                verbose=False,
                n_threads=4  # 성능 최적화
            )
            print("모델 로딩 완료.")
            return True
        else:
            print(f"경고: 모델 파일을 찾을 수 없습니다. 경로: {model_path}")
            print(f"설정된 경로: {settings.MODEL_PATH}")
            return False
    except Exception as e:
        print(f"모델 로딩 실패: {e}")
        return False

def _get_llm_json_response(prompt: str, max_tokens: int = 1024) -> dict:
    """
    LLM에 프롬프트를 보내고 JSON 응답을 안전하게 추출
    """
    if llm is None:
        print("오류: LLM 모델이 로드되지 않았습니다.")
        return {}

    try:
        output = llm(
            prompt,
            max_tokens=max_tokens,
            stop=["```", "</json>"],
            temperature=settings.AI_TEMPERATURE,
            echo=False
        )

        response_text = output["choices"][0]["text"].strip()

        # JSON 추출
        start_index = response_text.find('{')
        end_index = response_text.rfind('}')

        if start_index != -1 and end_index != -1 and start_index < end_index:
            json_string = response_text[start_index:end_index + 1]
            return json.loads(json_string)
        else:
            print(f"유효한 JSON을 찾을 수 없습니다: {response_text}")
            return {}

    except json.JSONDecodeError as e:
        print(f"JSON 파싱 오류: {e}")
        print(f"원본 응답: {response_text}")
        return {}
    except Exception as e:
        print(f"LLM 호출 오류: {e}")
        return {}

def analyze_voc_content(text: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    긴 텍스트(회의록, 메일, 녹취록 등)를 분석하여 VOC 형태로 구조화

    Args:
        text: 분석할 텍스트 (회의록, 메일, 녹취록 등)
        context: 추가 컨텍스트 정보 (회사명, 프로젝트명 등)

    Returns:
        Dict: VOC 구조화 결과
    """
    context_str = ""
    if context:
        context_str = f"컨텍스트 정보: {json.dumps(context, ensure_ascii=False, indent=2)}"

    prompt = f"""<|system|>
당신은 고객 VOC(Voice of Customer) 분석 전문가입니다.
다음 텍스트를 분석하여 VOC 데이터베이스에 저장할 수 있는 구조화된 정보로 변환해주세요.

분석 기준:
1. 고객의 핵심 요구사항과 문제점 파악
2. 실행 가능한 액션 아이템 추출
3. 우선순위 판단 (urgent/high/medium/low)
4. 현재 상태 분석 (in_progress/pending/completed/cancelled)
5. 감정 분석 (positive/negative/neutral)
6. 마감일 또는 일정 추출

{context_str}

<|user|>
--- 분석할 텍스트 ---
{text}
-----------------------

다음 JSON 형식으로 응답해주세요:
```json
{{
    "content_summary": "고객 VOC의 핵심 내용 요약 (200자 이내)",
    "action_items": ["실행해야 할 구체적 액션 1", "액션 2"],
    "priority": "urgent|high|medium|low",
    "status": "in_progress|pending|completed|cancelled",
    "due_date": "YYYY-MM-DD 형식 또는 null",
    "key_points": ["주요 포인트 1", "주요 포인트 2"],
    "sentiment": "positive|negative|neutral",
    "entities": {{
        "company": "회사명",
        "contacts": ["관련 인물들"],
        "products": ["언급된 제품/서비스"],
        "issues": ["문제점들"]
    }}
}}
```

<|assistant|>
```json
"""

    return _get_llm_json_response(prompt, max_tokens=1024)

def analyze_project_content(text: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    텍스트를 분석하여 프로젝트 정보로 구조화

    Args:
        text: 분석할 텍스트
        context: 추가 컨텍스트 정보

    Returns:
        Dict: 프로젝트 구조화 결과
    """
    context_str = ""
    if context:
        context_str = f"컨텍스트 정보: {json.dumps(context, ensure_ascii=False, indent=2)}"

    prompt = f"""<|system|>
당신은 프로젝트 관리 및 기술 분석 전문가입니다.
다음 텍스트를 분석하여 프로젝트 데이터베이스에 저장할 수 있는 구조화된 정보로 변환해주세요.

분석 기준:
1. 프로젝트명과 분야 식별
2. 기술적 요구사항 추출
3. 타겟 애플리케이션 파악
4. AI 모델 및 성능 요구사항
5. 경쟁사 분석
6. 예상 결과 및 근본 원인 분석

{context_str}

<|user|>
--- 분석할 텍스트 ---
{text}
-----------------------

다음 JSON 형식으로 응답해주세요:
```json
{{
    "project_name": "프로젝트명",
    "field": "분야 (AI/ML/Computer Vision/NLP 등)",
    "target_app": "타겟 애플리케이션",
    "ai_model": "사용할 AI 모델",
    "requirements": "기술적 요구사항 상세 설명",
    "competitors": ["경쟁사1", "경쟁사2"],
    "expected_result": "예상 결과 및 목표",
    "root_cause_analysis": "문제의 근본 원인 분석",
    "technical_specs": {{
        "performance": "성능 요구사항",
        "power": "전력 요구사항",
        "size": "크기/용량 요구사항",
        "price": "가격 요구사항"
    }}
}}
```

<|assistant|>
```json
"""

    return _get_llm_json_response(prompt, max_tokens=1024)

def extract_contact_info(text: str) -> Dict[str, Any]:
    """
    텍스트에서 연락처 정보 추출 (ai_email.py 기반)
    """
    prompt = f"""<|system|>
당신은 한국어 및 영어 텍스트에서 연락처 정보를 추출하는 전문가입니다.
다음 텍스트에서 이름, 이메일, 전화번호, 회사명, 직급, 부서를 찾아서 JSON 형식으로 반환해주세요.
특정 정보를 찾을 수 없다면 null을 사용해주세요.

<|user|>
--- 텍스트 ---
{text}
--------------

<|assistant|>
```json
{{
    "name": "이름",
    "title": "직급",
    "email": "이메일@domain.com",
    "phone": "전화번호",
    "company": "회사명",
    "department": "부서명"
}}
```
"""

    return _get_llm_json_response(prompt, max_tokens=512)

def generate_ai_summary(voc_data: Dict[str, Any]) -> str:
    """
    VOC 데이터로부터 ai_summary 필드용 요약문 생성
    """
    prompt = f"""<|system|>
당신은 간결하고 명확한 요약 전문가입니다.
주어진 VOC 데이터를 바탕으로 데이터베이스 ai_summary 필드에 저장할 한 줄 요약문을 생성해주세요.
요약문은 100자 이내로 핵심 내용만 포함해야 합니다.

<|user|>
VOC 데이터: {json.dumps(voc_data, ensure_ascii=False, indent=2)}

<|assistant|>
"""

    result = _get_llm_json_response(prompt, max_tokens=256)
    return result.get("summary", "AI 요약 생성 실패") if result else "AI 요약 생성 실패"

def analyze_mixed_content(text: str) -> Dict[str, Any]:
    """
    텍스트 유형을 자동 판별하고 적절한 분석 수행

    Returns:
        Dict: {
            "content_type": "voc|project|contact|mixed",
            "voc_analysis": {...},
            "project_analysis": {...},
            "contact_info": {...}
        }
    """
    # 먼저 텍스트 유형 판별
    type_prompt = f"""<|system|>
다음 텍스트를 분석하여 주된 내용이 무엇인지 판별해주세요.

유형:
- voc: 고객 불만, 요구사항, 피드백, 문제 보고
- project: 프로젝트 계획, 기술 사양, 개발 요구사항
- contact: 연락처, 자기소개, 명함 정보
- mixed: 여러 유형이 혼재

<|user|>
{text}

<|assistant|>
```json
{{"content_type": "voc|project|contact|mixed"}}
```
"""

    type_result = _get_llm_json_response(type_prompt, max_tokens=128)
    content_type = type_result.get("content_type", "mixed")

    result = {"content_type": content_type}

    # 유형에 따라 적절한 분석 수행
    if content_type in ["voc", "mixed"]:
        result["voc_analysis"] = analyze_voc_content(text)

    if content_type in ["project", "mixed"]:
        result["project_analysis"] = analyze_project_content(text)

    if content_type in ["contact", "mixed"]:
        result["contact_info"] = extract_contact_info(text)

    return result

# 초기화 함수
def init_ai_utils():
    """AI 유틸리티 초기화"""
    return initialize_llm()

# 테스트 함수
def test_ai_functions():
    """AI 기능 테스트"""
    if not llm:
        print("모델이 로드되지 않아 테스트를 건너뜁니다.")
        return False

    # VOC 분석 테스트
    test_voc_text = """
    안녕하세요. 저희 회사에서 사용 중인 AI 모델의 성능이 기대에 못 미치고 있습니다.
    특히 한국어 처리 정확도가 70% 정도밖에 안 되고, 응답 속도도 너무 느립니다.
    다음 주까지 개선 방안을 제시해 주시면 좋겠습니다.
    담당자: 김철수 부장 (kimcs@company.com, 010-1234-5678)
    """

    print("=== VOC 분석 테스트 ===")
    voc_result = analyze_voc_content(test_voc_text)
    print(json.dumps(voc_result, ensure_ascii=False, indent=2))

    return True

if __name__ == "__main__":
    # 테스트 실행
    if init_ai_utils():
        test_ai_functions()
    else:
        print("AI 유틸리티 초기화 실패")