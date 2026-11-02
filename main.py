import os
import math
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional
import uuid
import shutil
import base64
from openai import OpenAI


import jwt
from fastapi import FastAPI, Depends, HTTPException, status, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi import File, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean,
    DateTime, ForeignKey, Text, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

import bcrypt

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# ==========================================
# 1. 환경 설정 및 데이터베이스 초기화
# ==========================================
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "memory-coordinates-dandithon-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24시간
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")  # 설정 시 실제 OpenAI API 호출, 미설정 시 내장 AI 엔진 동작
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./memory_coordinates.db")
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()




# ==========================================
# 2. Enum 정의 (와이어프레임 상태값 반영)
# ==========================================
class AuthProvider(str, Enum):
    LOCAL = "LOCAL"
    KAKAO = "KAKAO"
    APPLE = "APPLE"


class VisitVerifyMethod(str, Enum):
    GPS = "GPS"
    QR = "QR"
    PHOTO = "PHOTO"


class VerifyStatus(str, Enum):
    SUCCESS = "SUCCESS"   # 성공
    FAILED = "FAILED"     # 실패 (거리 초과, 조건 미달 등)
    PENDING = "PENDING"   # 대기 (심사 중)
    ERROR = "ERROR"       # 처리 오류


# ==========================================
# 3. 데이터베이스 모델 (SQLAlchemy ORM)
# ==========================================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)  # 소셜 로그인은 null 가능
    nickname = Column(String(50), nullable=False)
    provider = Column(String(20), default=AuthProvider.LOCAL.value)
    extra_info = Column(String(255), nullable=True)     # S18, S19 추가 정보 필드
    created_at = Column(DateTime, default=datetime.utcnow)

    visits = relationship("PlaceVisit", back_populates="user")
    user_missions = relationship("UserMission", back_populates="user")
    rewards = relationship("UserReward", back_populates="user")


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(500), unique=True, index=True, nullable=False)
    blacklisted_at = Column(DateTime, default=datetime.utcnow)


class Place(Base):
    __tablename__ = "places"

    id = Column(Integer, primary_key=True, index=True)
    pin_code = Column(String(10), nullable=False)       # 지도 핀 라벨 (A, B, C 등)
    name = Column(String(100), nullable=False)          # 장소명
    address = Column(String(255), nullable=False)       # 위치/주소 정보
    summary = Column(String(255), nullable=False)       # 지도 요약 카드 설명
    description = Column(Text, nullable=False)          # 장소 상세 설명
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    image_url = Column(String(500), nullable=True)      # S05 장소 이미지 (선택 항목)
    qr_secret = Column(String(100), nullable=True)      # QR 인증 시 검증 코드

    historical_photos = relationship("HistoricalPhoto", back_populates="place")
    missions = relationship("Mission", back_populates="place")


class HistoricalPhoto(Base):
    __tablename__ = "historical_photos"

    id = Column(Integer, primary_key=True, index=True)
    place_id = Column(Integer, ForeignKey("places.id"), nullable=False)
    image_url = Column(String(500), nullable=False)
    taken_year = Column(String(50), nullable=False)     # S08 확인된 촬영 시기(연도)
    source = Column(String(255), nullable=False)        # S08 원문/기관 출처 정보
    caption = Column(Text, nullable=True)               # 과거 사진 설명

    place = relationship("Place", back_populates="historical_photos")


class PlaceVisit(Base):
    __tablename__ = "place_visits"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    place_id = Column(Integer, ForeignKey("places.id"), nullable=False)
    verify_method = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False)         # SUCCESS, FAILED, ERROR
    reason = Column(String(255), nullable=True)         # S06, S07 실패/오류 사유 별도 표시
    verified_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="visits")
    place = relationship("Place")


class Mission(Base):
    __tablename__ = "missions"

    id = Column(Integer, primary_key=True, index=True)
    place_id = Column(Integer, ForeignKey("places.id"), nullable=False)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    step_guides = Column(Text, nullable=False)          # JSON 문자열: S09 1~3단계 수행 안내
    verification_criteria = Column(Text, nullable=False) # AI가 인증 심사 시 참고할 기준
    reward_name = Column(String(100), nullable=False)
    reward_detail = Column(String(255), nullable=False)
    reward_quantity = Column(Integer, default=1)
    created_by_ai = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    place = relationship("Place", back_populates="missions")


class UserMission(Base):
    __tablename__ = "user_missions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    mission_id = Column(Integer, ForeignKey("missions.id"), nullable=False)
    place_id = Column(Integer, ForeignKey("places.id"), nullable=False)
    proof_text = Column(Text, nullable=True)            # S10 사용자 제출 텍스트
    proof_image_url = Column(String(500), nullable=True)# S10 사용자 제출 이미지 URL
    status = Column(String(20), default=VerifyStatus.PENDING.value)  # S11 성공/실패/오류/대기
    ai_feedback = Column(String(500), nullable=True)    # S11 거절 사유 또는 AI 심사 코멘트
    submitted_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="user_missions")
    mission = relationship("Mission")
    place = relationship("Place")


class UserReward(Base):
    __tablename__ = "user_rewards"
    __table_args__ = (
        UniqueConstraint("user_id", "user_mission_id", name="uq_user_mission_reward"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user_mission_id = Column(Integer, ForeignKey("user_missions.id"), nullable=False)
    place_id = Column(Integer, ForeignKey("places.id"), nullable=False)
    reward_name = Column(String(100), nullable=False)   # S12, S13 보상명
    reward_detail = Column(String(255), nullable=False) # S13 지급 내용/상세정보
    quantity = Column(Integer, default=1)               # S13 지급 수량
    issued_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="rewards")
    user_mission = relationship("UserMission")
    place = relationship("Place")


Base.metadata.create_all(bind=engine)


# ==========================================
# 4. Pydantic 스키마 (Request / Response DTO)
# ==========================================
class SignupRequest(BaseModel):
    account_id: str = Field(..., min_length=4, max_length=50, description="로그인 계정 ID")
    password: str = Field(..., min_length=6, description="비밀번호")
    password_confirm: str = Field(..., min_length=6, description="비밀번호 확인 (S02)")
    nickname: Optional[str] = Field(None, description="닉네임 (미입력 시 계정 ID 기반 자동 생성)")


class LoginRequest(BaseModel):
    account_id: str
    password: str


class OAuthLoginRequest(BaseModel):
    provider: AuthProvider = Field(..., description="KAKAO 또는 APPLE (단디플로우 반영)")
    oauth_token: str = Field(..., description="소셜 인증 토큰 또는 고유 식별자")
    nickname: Optional[str] = Field(None, description="최초 가입 시 설정할 닉네임")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    account_id: str
    nickname: str


class PlacePinResponse(BaseModel):
    id: int
    pin_code: str
    name: str
    address: str
    summary: str
    latitude: float
    longitude: float
    distance_meters: Optional[float] = None


class PlaceDetailResponse(BaseModel):
    id: int
    pin_code: str
    name: str
    address: str
    summary: str
    description: str
    latitude: float
    longitude: float
    image_url: Optional[str] = None
    is_visited: bool = False
    guide_message: str = "이 장소에 방문하면 연결된 과거 사진과 장소 관련 미션을 확인할 수 있어요."


class VisitVerifyRequest(BaseModel):
    verify_method: VisitVerifyMethod = Field(default=VisitVerifyMethod.GPS)
    latitude: Optional[float] = Field(None, description="GPS 인증 시 현재 위도")
    longitude: Optional[float] = Field(None, description="GPS 인증 시 현재 경도")
    qr_code: Optional[str] = Field(None, description="QR 인증 시 스캔한 코드")
    photo_url: Optional[str] = Field(None, description="사진 인증 시 업로드한 이미지 URL")


class VisitVerifyResponse(BaseModel):
    visit_id: int
    place_id: int
    place_name: str
    status: VerifyStatus
    reason: Optional[str] = None
    can_view_historical_photos: bool
    verified_at: datetime


class HistoricalPhotoItem(BaseModel):
    id: int
    image_url: str
    taken_year: str
    source: str
    caption: Optional[str] = None


class HistoricalPhotoListResponse(BaseModel):
    place_id: int
    place_name: str
    has_photos: bool
    empty_message: Optional[str] = None
    photos: List[HistoricalPhotoItem]


class MissionResponse(BaseModel):
    mission_id: int
    place_id: int
    place_name: str
    title: str
    content: str
    step_guides: List[str]
    reward_name: str
    reward_detail: str
    created_by_ai: bool


class MissionSubmitRequest(BaseModel):
    proof_text: Optional[str] = Field(None, description="미션 수행 텍스트 인증 내용 (소감, 퀴즈 정답, 관찰 기록 등)")
    proof_image_url: Optional[str] = Field(None, description="미션 인증 사진 URL")


class MissionVerifyResultResponse(BaseModel):
    submission_id: int
    mission_id: int
    place_id: int
    status: VerifyStatus
    ai_feedback: str
    can_claim_reward: bool
    submitted_at: datetime


class RewardClaimRequest(BaseModel):
    submission_id: int = Field(..., description="승인(SUCCESS)된 미션 제출 ID")


class RewardResponse(BaseModel):
    reward_id: int
    place_id: int
    place_name: str
    reward_name: str
    reward_detail: str
    quantity: int
    issued_status: str = "COMPLETED"
    issued_at: datetime


class ProfileUpdateRequest(BaseModel):
    nickname: Optional[str] = Field(None, min_length=2, max_length=50)
    extra_info: Optional[str] = Field(None, max_length=255)


# ==========================================
# 5. 유틸리티 및 AI 미션 생성·검증 엔진
# ==========================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


security = HTTPBearer()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    token = credentials.credentials
    
    # 1. 로그아웃(블랙리스트) 체크
    if db.query(TokenBlacklist).filter(TokenBlacklist.token == token).first():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="로그아웃된 토큰입니다. 다시 로그인해 주세요."
        )
    
    # 2. 토큰 검증
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 인증 정보입니다.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="세션이 만료되었습니다. 재로그인해 주세요.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="존재하지 않는 계정입니다.")
    return user


def calculate_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine 공식을 이용한 두 좌표 간 거리(m) 계산"""
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))

def _resolve_image_for_vision(image_url: str) -> Optional[str]:
    """로컬 서버에 업로드된 이미지 URL인 경우 Base64 Data URL로 변환하고, 외부 URL은 그대로 반환합니다."""
    if not image_url:
        return None

    if "/uploads/" in image_url:
        filename = image_url.split("/uploads/")[-1]
        local_path = os.path.join("./uploads", filename)
        if os.path.exists(local_path):
            ext = filename.split(".")[-1].lower()
            mime_type = "image/png" if ext == "png" else "image/jpeg"
            with open(local_path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("utf-8")
            return f"data:{mime_type};base64,{encoded}"
    elif image_url.startswith("http://") or image_url.startswith("https://"):
        return image_url
    return None

def generate_ai_mission_for_place(place: Place, photos: List[HistoricalPhoto]) -> dict:
    """
    [5.1.1 미션 제시 / S09]
    장소 상세 설명(description)과 과거 사진(taken_year, source, caption)을 프롬프트로 구성하여
    GPT가 현장 맞춤형 미션과 1~3단계 수행 가이드를 JSON 형태로 실시간 생성합니다.
    """
    if photos:
        photo_descriptions = "\n".join(
            [f"- 촬영연도: {p.taken_year} / 출처: {p.source} / 설명: {p.caption}" for p in photos]
        )
    else:
        photo_descriptions = "- 등록된 과거 사진 없음 (장소의 역사적 배경을 중심으로 미션 구성)"

    # API 키 미설정 또는 네트워크 장애 시 사용할 안전 폴백(Fallback) 데이터
    fallback_mission = {
        "title": f"[기억 탐색] {place.name}의 어제와 오늘 잇기",
        "content": f"과거 기록 속 지점과 같은 시선으로 현재의 '{place.name}'을(를) 바라보고, 가장 크게 달라진 풍경이나 변치 않고 남아 있는 흔적 1가지를 찾아 사진 또는 기록으로 남겨주세요.",
        "step_guides": [
            "1. 제공된 과거 사진 속 건물 윤곽이나 주변 지형지물을 먼저 확인해 주세요.",
            f"2. 현재 {place.name} 현장에서 과거 사진과 가장 비슷한 구도를 찾아 관찰하며 미션을 수행해요.",
            "3. 발견한 변화나 현장 인증샷(또는 10자 이상의 관찰 기록)을 첨부해 인증 자료를 제출해요."
        ],
        "verification_criteria": f"{place.name} 현장 관찰 내용(과거와 현재 비교, 건축물/거리 특징) 또는 현장 사진 포함 여부",
        "reward_name": f"{place.name} 기억 조각 스탬프 & 500 로컬 포인트",
        "reward_detail": f"대구·경북 기억 아카이브 [{place.pin_code}구역: {place.name}] 공식 탐색 완료 디지털 배지 및 500P"
    }

    if not openai_client:
        return fallback_mission

    system_prompt = (
        "당신은 대구·경북 지역 기억 아카이브 서비스 '기억의 좌표(로컬퀘스트)'의 AI 퀘스트 디렉터입니다. "
        "사용자가 현장에 방문해 과거 사진 기록과 현재의 풍경을 비교·관찰하며 수행할 수 있는 몰입감 있는 현장 미션을 설계하세요. "
        "반드시 아래 JSON 스키마 키를 정확히 지키는 JSON 객체만 응답해야 합니다:\n"
        "{\n"
        '  "title": "미션 제목 (예: [AI 기억 탐색] ...)",\n'
        '  "content": "수행할 미션의 핵심 본문 설명 (2~3문장)",\n'
        '  "step_guides": ["1. 첫 번째 단계 안내", "2. 두 번째 단계 안내", "3. 세 번째 단계 안내 (정확히 3개 원소 배열)"],\n'
        '  "verification_criteria": "나중에 AI 심사관이 사용자의 제출 텍스트/사진을 승인할 때 확인할 구체적인 통과 기준",\n'
        '  "reward_name": "보상 이름 (예: 계산성당 기억 조각 스탬프 & 500 로컬 포인트)",\n'
        '  "reward_detail": "보상 상세 설명"\n'
        "}"
    )

    user_prompt = (
        f"[장소 정보]\n"
        f"- 핀 코드: {place.pin_code}\n"
        f"- 장소명: {place.name}\n"
        f"- 주소: {place.address}\n"
        f"- 상세 설명: {place.description}\n\n"
        f"[연결된 과거 사진 아카이브]\n"
        f"{photo_descriptions}\n\n"
        f"위 장소와 과거 사진 맥락을 반영하여 사용자가 현장에서 직접 눈으로 찾거나 촬영·기록할 수 있는 미션을 JSON으로 생성해 주세요."
    )

    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=700
        )
        result = json.loads(response.choices[0].message.content)

        # 필수 키 검증 및 보정
        for key in fallback_mission.keys():
            if key not in result or not result[key]:
                result[key] = fallback_mission[key]
        if not isinstance(result.get("step_guides"), list) or len(result["step_guides"]) != 3:
            result["step_guides"] = fallback_mission["step_guides"]

        return result
    except Exception as e:
        print(f"[OpenAI 미션 생성 예외 발생 - Fallback 동작]: {e}")
        return fallback_mission


def evaluate_mission_with_ai(
    mission: Mission,
    proof_text: Optional[str],
    proof_image_url: Optional[str]
) -> tuple[VerifyStatus, str]:
    """
    [5.3.2~5.3.3 미션 인증하기 및 결과 확인 / S10, S11]
    사용자가 제출한 텍스트(proof_text)와 이미지(proof_image_url)를 GPT-4o-mini Vision으로 함께 분석하여
    SUCCESS(승인), FAILED(거절 및 사유), ERROR(처리 오류)를 판정합니다.
    """
    if not proof_text and not proof_image_url:
        return (
            VerifyStatus.FAILED,
            "거절 사유: 제출된 인증 텍스트나 사진 자료가 없습니다. 미션 인증 자료를 첨부해 주세요."
        )

    if not openai_client:
        if proof_text and len(proof_text.strip()) < 10 and not proof_image_url:
            return (
                VerifyStatus.FAILED,
                "거절 사유: 작성된 관찰 기록이 너무 짧습니다(10자 이상 작성 필요). 장소의 특징을 조금 더 구체적으로 적어주세요."
            )
        return (
            VerifyStatus.SUCCESS,
            f"AI 인증 심사 승인: '{mission.place.name}'의 현장 기록이 확인되었습니다."
        )

    system_prompt = (
        "당신은 대구·경북 기억 아카이브 서비스 '기억의 좌표'의 공정한 AI 미션 심사관입니다. "
        "제시된 미션 내용과 심사 기준을 바탕으로 사용자가 제출한 텍스트 및 이미지가 미션 의도에 부합하는지 평가하세요. "
        "의미 없는 문자열(예: 'ㅋㅋㅋㅋ', '1234', '테스트')이나 장소와 전혀 무관한 내용은 반드시 FAILED 처리하고 구체적인 거절 사유를 안내하세요. "
        "반드시 아래 JSON 형식으로만 응답하세요:\n"
        "{\n"
        '  "status": "SUCCESS" 또는 "FAILED",\n'
        '  "feedback": "승인 축하 코멘트 또는 구체적인 거절 사유 (한국어 1~2문장)"\n'
        "}"
    )

    text_context = (
        f"[장소명]: {mission.place.name}\n"
        f"[미션 제목]: {mission.title}\n"
        f"[미션 내용]: {mission.content}\n"
        f"[심사 기준]: {mission.verification_criteria}\n"
        f"[사용자 제출 텍스트]: {proof_text if proof_text else '(텍스트 미제출)'}\n"
        f"[사용자 제출 이미지 여부]: {'첨부됨' if proof_image_url else '미첨부'}"
    )

    user_content = [{"type": "text", "text": text_context}]

    # 이미지가 첨부된 경우 로컬/외부 이미지를 Vision 입력으로 추가
    vision_image_url = _resolve_image_for_vision(proof_image_url) if proof_image_url else None
    if vision_image_url:
        user_content.append({
            "type": "image_url",
            "image_url": {"url": vision_image_url}
        })

    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            temperature=0.2,
            max_tokens=300
        )
        result = json.loads(response.choices[0].message.content)
        status_str = result.get("status", "FAILED").upper()
        feedback = result.get("feedback", "AI 심사가 완료되었습니다.")

        if status_str == "SUCCESS":
            return VerifyStatus.SUCCESS, feedback
        return VerifyStatus.FAILED, feedback
    except Exception as e:
        print(f"[OpenAI 미션 심사 예외 발생]: {e}")
        return (
            VerifyStatus.ERROR,
            "처리 오류: AI 심사 서버와의 통신 중 일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."
        )

# ==========================================
# 6. FastAPI 앱 생성 및 초기 데이터 시딩
# ==========================================
app = FastAPI(
    title="기억의 좌표 (로컬퀘스트) Backend API",
    description="기능명세서(1.1~7.3) 및 모바일 웹 와이어프레임(S01~S20) 기반 AI 미션·보상 아카이브 백엔드 서버",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. 로컬 업로드 디렉토리 생성
UPLOAD_DIR = "./uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 2. 클라이언트가 URL로 이미지에 접근할 수 있도록 Static 경로 마운트
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


@app.on_event("startup")
def seed_initial_data():
    db = SessionLocal()
    try:
        if db.query(Place).count() == 0:
            places_seed = [
                Place(
                    pin_code="A",
                    name="계산성당 역사거리",
                    address="대구광역시 중구 서성로 10",
                    summary="계산성당 - 대구 중구 서성로 10 (1902년 건립 근대 건축)",
                    description="대구 최초의 서양식 성당 건축물로, 100년이 넘는 세월 동안 대구의 근현대사를 간직한 상징적 공간입니다.",
                    latitude=35.8679,
                    longitude=128.5878,
                    image_url="https://images.unsplash.com/photo-1548625361-16800b328a79?auto=format&fit=crop&w=800&q=80",
                    qr_secret="QR_PLACE_A_2026"
                ),
                Place(
                    pin_code="B",
                    name="청라언덕과 3·1만세운동길",
                    address="대구광역시 중구 달구벌대로 2029",
                    summary="청라언덕 - 대구 중구 달구벌대로 2029 (근대문화골목)",
                    description="푸른 담쟁이덩굴로 덮인 선교사 주택과 90계단 위 대구의 시대적 풍경이 교차하는 역사 아카이브 지점입니다.",
                    latitude=35.8665,
                    longitude=128.5843,
                    image_url="https://images.unsplash.com/photo-1513635269975-59663e0ac1ad?auto=format&fit=crop&w=800&q=80",
                    qr_secret="QR_PLACE_B_2026"
                ),
                Place(
                    pin_code="C",
                    name="북성로 공구골목 구 삼덕상회",
                    address="대구광역시 중구 북성로 48",
                    summary="북성로 공구골목 - 대구 중구 북성로 48 (근대 산업 유산)",
                    description="일제강점기 미나카이 백화점 인근 상권에서 출발해 전후 산업화를 이끈 기술 장인들의 기억이 서린 골목입니다.",
                    latitude=35.8738,
                    longitude=128.5912,
                    image_url="https://images.unsplash.com/photo-1519501025264-65ba15a82390?auto=format&fit=crop&w=800&q=80",
                    qr_secret="QR_PLACE_C_2026"
                ),
            ]
            db.add_all(places_seed)
            db.commit()

            photos_seed = [
                HistoricalPhoto(
                    place_id=places_seed[0].id,
                    image_url="https://example.com/archive/gyesan_1920.jpg",
                    taken_year="1926년경 확인",
                    source="국립대구박물관 근대사진 아카이브 / 원문 대조 완료",
                    caption="첨탑 주변으로 낮은 기와집들이 펼쳐져 있던 1920년대 계산성당 일대 전경"
                ),
                HistoricalPhoto(
                    place_id=places_seed[1].id,
                    image_url="https://example.com/archive/cheongna_1935.jpg",
                    taken_year="1935년 확인",
                    source="대구광역시 근대문화골목 디지털 기록관",
                    caption="90계단 위에서 내려다본 옛 대구 시가지와 시내전차 노선 흔적"
                ),
            ]
            db.add_all(photos_seed)
            db.commit()
    finally:
        db.close()


# ==========================================
# 7. API 엔드포인트 구현 (기능명세서 1.1 ~ 7.3)
# ==========================================

# ------------------------------------------
# [섹션 1] 로그인 / 회원가입 (명세 1.1 ~ 1.2 / 화면 S01, S02, S20)
# ------------------------------------------
@app.post("/api/v1/auth/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED, tags=["1. 인증/계정 (S01-S02, S20)"])
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    """[1.1.1 회원가입 / S02] 계정·비밀번호·비밀번호 확인 검증 후 신규 계정을 생성합니다."""
    if req.password != req.password_confirm:
        raise HTTPException(status_code=400, detail="비밀번호와 비밀번호 확인 입력값이 일치하지 않습니다.")
    if db.query(User).filter(User.account_id == req.account_id).first():
        raise HTTPException(status_code=409, detail="이미 사용 중인 계정입니다.")

    nickname = req.nickname if req.nickname else f"기억탐색자_{req.account_id[:6]}"
    user = User(
        account_id=req.account_id,
        password_hash=get_password_hash(req.password),
        nickname=nickname,
        provider=AuthProvider.LOCAL.value
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id})
    return TokenResponse(access_token=token, user_id=user.id, account_id=user.account_id, nickname=user.nickname)


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["1. 인증/계정 (S01-S02, S20)"])
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """[1.2.1 로그인 / S01] 계정 및 비밀번호를 검증하고 JWT 액세스 토큰을 발급합니다."""
    user = db.query(User).filter(User.account_id == req.account_id).first()
    if not user or not user.password_hash or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="입력 오류 또는 로그인 실패: 계정이나 비밀번호를 다시 확인해 주세요.")

    token = create_access_token({"sub": user.id})
    return TokenResponse(access_token=token, user_id=user.id, account_id=user.account_id, nickname=user.nickname)


@app.post("/api/v1/auth/oauth", response_model=TokenResponse, tags=["1. 인증/계정 (S01-S02, S20)"])
def oauth_login(req: OAuthLoginRequest, db: Session = Depends(get_db)):
    """[단디플로우 간편 로그인/회원가입] 카카오·애플 소셜 토큰으로 로그인하거나 신규 가입 및 닉네임을 설정합니다."""
    social_account_id = f"{req.provider.value.lower()}_{req.oauth_token[:16]}"
    user = db.query(User).filter(User.account_id == social_account_id).first()

    if not user:
        nickname = req.nickname if req.nickname else f"{req.provider.value}_탐색자"
        user = User(
            account_id=social_account_id,
            password_hash=None,
            nickname=nickname,
            provider=req.provider.value
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token({"sub": user.id})
    return TokenResponse(access_token=token, user_id=user.id, account_id=user.account_id, nickname=user.nickname)


@app.get("/api/v1/auth/status", tags=["1. 인증/계정 (S01-S02, S20)"])
def check_auth_status(current_user: User = Depends(get_current_user)):
    """[1.2.2 로그인 상태 확인] 현재 로그인 여부 및 서비스 이용 권한을 확인합니다."""
    return {
        "is_Authenticated": True,
        "user_id": current_user.id,
        "account_id": current_user.account_id,
        "nickname": current_user.nickname,
        "provider": current_user.provider
    }


@app.post("/api/v1/auth/logout", tags=["1. 인증/계정 (S01-S02, S20)"])
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    db.add(TokenBlacklist(token=token))
    db.commit()
    return {
        "message": "안전하게 로그아웃되었습니다. 기존 방문 기록 및 보상 내역은 계정에 보존됩니다.",
        "user_id": current_user.id
    }


# ------------------------------------------
# [섹션 2] 메인페이지 지도 및 추천 장소 (명세 2.1 ~ 2.2, 6.3 / 화면 S03, S04, S05)
# ------------------------------------------
@app.get("/api/v1/places/recommendations", response_model=List[PlacePinResponse], tags=["2. 지도 및 추천 장소 (S03-S05)"])
def get_recommended_places(
    latitude: Optional[float] = Query(None, description="사용자 현재 위도 (위치 권한 허용 시 전달, 거부 시 미전달 가능)"),
    longitude: Optional[float] = Query(None, description="사용자 현재 경도 (위치 권한 허용 시 전달, 거부 시 미전달 가능)"),
    db: Session = Depends(get_db)
):
    """
    [2.1.1~2.2.1 추천 장소 핀 표시 / S03, S04]
    위치 권한을 거부해 좌표가 없더라도 기본 추천 장소 핀(A, B, C)을 반환하며, 좌표 전달 시 현재 위치로부터의 거리를 계산해 정렬합니다.
    """
    places = db.query(Place).all()
    results = []
    for p in places:
        dist = None
        if latitude is not None and longitude is not None:
            dist = round(calculate_distance_meters(latitude, longitude, p.latitude, p.longitude), 1)
        results.append(
            PlacePinResponse(
                id=p.id,
                pin_code=p.pin_code,
                name=p.name,
                address=p.address,
                summary=p.summary,
                latitude=p.latitude,
                longitude=p.longitude,
                distance_meters=dist
            )
        )
    if latitude is not None and longitude is not None:
        results.sort(key=lambda x: x.distance_meters if x.distance_meters is not None else float("inf"))
    return results


@app.get("/api/v1/places/{place_id}", response_model=PlaceDetailResponse, tags=["2. 지도 및 추천 장소 (S03-S05)"])
def get_place_detail(
    place_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[2.2.2~2.2.3 장소 상세 조회 / S05] 선택한 추천 장소 핀의 상세 정보와 현재 사용자의 방문 인증 여부를 반환합니다."""
    place = db.query(Place).filter(Place.id == place_id).first()
    if not place:
        raise HTTPException(status_code=404, detail="선택한 장소를 찾을 수 없습니다.")

    visited = db.query(PlaceVisit).filter(
        PlaceVisit.user_id == current_user.id,
        PlaceVisit.place_id == place_id,
        PlaceVisit.status == VerifyStatus.SUCCESS.value
    ).first() is not None

    return PlaceDetailResponse(
        id=place.id,
        pin_code=place.pin_code,
        name=place.name,
        address=place.address,
        summary=place.summary,
        description=place.description,
        latitude=place.latitude,
        longitude=place.longitude,
        image_url=place.image_url,
        is_visited=visited
    )


# ------------------------------------------
# [섹션 3] 장소 방문 인증 및 과거 사진 (명세 3.1 ~ 4.1 / 화면 S06, S07, S08)
# ------------------------------------------
@app.post("/api/v1/places/{place_id}/verify-visit", response_model=VisitVerifyResponse, tags=["3. 장소 인증 및 과거 사진 (S06-S08)"])
def verify_place_visit(
    place_id: int,
    req: VisitVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [3.1.1~3.1.3 장소 방문 인증 요청 및 결과 확인 / S06, S07]
    GPS(반경 300m 이내), QR 코드, 사진 인증 방식을 모두 수용하며 성공·실패·오류 사유를 명확히 구분해 저장 및 반환합니다.
    """
    place = db.query(Place).filter(Place.id == place_id).first()
    if not place:
        raise HTTPException(status_code=404, detail="인증 대상 장소를 찾을 수 없습니다.")

    verify_status = VerifyStatus.FAILED
    reason = None

    if req.verify_method == VisitVerifyMethod.GPS:
        if req.latitude is None or req.longitude is None:
            verify_status = VerifyStatus.ERROR
            reason = "위치 권한이 꺼져 있거나 현재 위치 좌표를 확인할 수 없습니다."
        else:
            distance = calculate_distance_meters(req.latitude, req.longitude, place.latitude, place.longitude)
            if distance <= 300.0:
                verify_status = VerifyStatus.SUCCESS
                reason = f"방문 인증 완료 (장소 반경 {int(distance)}m 이내 확인)"
            else:
                verify_status = VerifyStatus.FAILED
                reason = f"선택한 장소와 거리가 멉니다(현재 약 {int(distance)}m 거리). 장소 반경 300m 이내에서 다시 시도해 주세요."
    elif req.verify_method == VisitVerifyMethod.QR:
        if req.qr_code and req.qr_code == place.qr_secret:
            verify_status = VerifyStatus.SUCCESS
            reason = "현장 QR 코드 인증이 완료되었습니다."
        else:
            verify_status = VerifyStatus.FAILED
            reason = "유효하지 않은 현장 QR 코드입니다."
    elif req.verify_method == VisitVerifyMethod.PHOTO:
        if req.photo_url:
            verify_status = VerifyStatus.SUCCESS
            reason = "현장 방문 사진 인증이 완료되었습니다."
        else:
            verify_status = VerifyStatus.ERROR
            reason = "방문 인증 사진이 정상적으로 첨부되지 않았습니다."

    visit = PlaceVisit(
        user_id=current_user.id,
        place_id=place.id,
        verify_method=req.verify_method.value,
        status=verify_status.value,
        reason=reason
    )
    db.add(visit)
    db.commit()
    db.refresh(visit)

    return VisitVerifyResponse(
        visit_id=visit.id,
        place_id=place.id,
        place_name=place.name,
        status=verify_status,
        reason=reason,
        can_view_historical_photos=(verify_status == VerifyStatus.SUCCESS),
        verified_at=visit.verified_at
    )


@app.get("/api/v1/places/{place_id}/historical-photos", response_model=HistoricalPhotoListResponse, tags=["3. 장소 인증 및 과거 사진 (S06-S08)"])
def get_historical_photos(
    place_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [4.1.1~4.1.2 과거 사진 조회 / S08]
    방문 인증에 성공한 사용자에게만 해당 장소의 과거 사진(촬영 시기, 원문/기관 출처)을 반환하며, 사진이 없는 경우 안내 문구를 제공합니다.
    """
    place = db.query(Place).filter(Place.id == place_id).first()
    if not place:
        raise HTTPException(status_code=404, detail="장소를 찾을 수 없습니다.")

    verified_visit = db.query(PlaceVisit).filter(
        PlaceVisit.user_id == current_user.id,
        PlaceVisit.place_id == place_id,
        PlaceVisit.status == VerifyStatus.SUCCESS.value
    ).first()
    if not verified_visit:
        raise HTTPException(
            status_code=403,
            detail="장소 방문 인증을 완료한 후에만 과거 사진을 열람할 수 있습니다. (S05/S07 정책)"
        )

    photos = db.query(HistoricalPhoto).filter(HistoricalPhoto.place_id == place_id).all()
    photo_items = [
        HistoricalPhotoItem(
            id=p.id,
            image_url=p.image_url,
            taken_year=p.taken_year,
            source=p.source,
            caption=p.caption
        )
        for p in photos
    ]

    return HistoricalPhotoListResponse(
        place_id=place.id,
        place_name=place.name,
        has_photos=len(photo_items) > 0,
        empty_message=None if len(photo_items) > 0 else "현재 검수 완료된 과거 사진 기록이 준비 중입니다. 미션 확인하기로 이동해 주세요.",
        photos=photo_items
    )


# ------------------------------------------
# [섹션 4] AI 미션 제시, 수행 및 인증 (명세 5.1 ~ 5.3 / 화면 S09, S10, S11)
# ------------------------------------------
@app.post("/api/v1/places/{place_id}/missions/generate", response_model=MissionResponse, tags=["4. AI 미션 및 인증 (S09-S11)"])
def generate_or_get_place_mission(
    place_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [5.1.1~5.2.1 AI 미션 제시 및 내용 확인 / S09]
    방문 인증이 완료된 장소에 대해 AI가 과거 사진과 장소 특성을 반영한 맞춤형 미션 및 1~3단계 수행 가이드를 생성·제공합니다.
    """
    place = db.query(Place).filter(Place.id == place_id).first()
    if not place:
        raise HTTPException(status_code=404, detail="장소를 찾을 수 없습니다.")

    verified_visit = db.query(PlaceVisit).filter(
        PlaceVisit.user_id == current_user.id,
        PlaceVisit.place_id == place_id,
        PlaceVisit.status == VerifyStatus.SUCCESS.value
    ).first()
    if not verified_visit:
        raise HTTPException(status_code=403, detail="장소 방문 인증 후 미션을 발급받을 수 있습니다.")

    mission = db.query(Mission).filter(Mission.place_id == place_id).first()
    if not mission:
        photos = db.query(HistoricalPhoto).filter(HistoricalPhoto.place_id == place_id).all()
        ai_data = generate_ai_mission_for_place(place, photos)
        mission = Mission(
            place_id=place.id,
            title=ai_data["title"],
            content=ai_data["content"],
            step_guides=json.dumps(ai_data["step_guides"], ensure_ascii=False),
            verification_criteria=ai_data["verification_criteria"],
            reward_name=ai_data["reward_name"],
            reward_detail=ai_data["reward_detail"],
            created_by_ai=True
        )
        db.add(mission)
        db.commit()
        db.refresh(mission)

    return MissionResponse(
        mission_id=mission.id,
        place_id=place.id,
        place_name=place.name,
        title=mission.title,
        content=mission.content,
        step_guides=json.loads(mission.step_guides),
        reward_name=mission.reward_name,
        reward_detail=mission.reward_detail,
        created_by_ai=mission.created_by_ai
    )


@app.post("/api/v1/missions/{mission_id}/submit", response_model=MissionVerifyResultResponse, tags=["4. AI 미션 및 인증 (S09-S11)"])
def submit_mission_proof(
    mission_id: int,
    req: MissionSubmitRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [5.3.1~5.3.3 미션 인증 자료 제출 및 AI 심사 결과 확인 / S10, S11]
    이미 승인된 미션의 중복 제출을 방지하며, 제출 자료를 AI가 평가해 성공(SUCCESS)/실패(FAILED)/오류(ERROR)/대기(PENDING)를 반환합니다.
    """
    mission = db.query(Mission).filter(Mission.id == mission_id).first()
    if not mission:
        raise HTTPException(status_code=404, detail="미션을 찾을 수 없습니다.")

    existing_success = db.query(UserMission).filter(
        UserMission.user_id == current_user.id,
        UserMission.mission_id == mission_id,
        UserMission.status == VerifyStatus.SUCCESS.value
    ).first()
    if existing_success:
        raise HTTPException(status_code=409, detail="이미 인증이 완료된 미션입니다. 중복 제출할 수 없습니다. (S10 중복 요청 방지)")

    eval_status, feedback = evaluate_mission_with_ai(mission, req.proof_text, req.proof_image_url)

    submission = UserMission(
        user_id=current_user.id,
        mission_id=mission.id,
        place_id=mission.place_id,
        proof_text=req.proof_text,
        proof_image_url=req.proof_image_url,
        status=eval_status.value,
        ai_feedback=feedback
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)

    return MissionVerifyResultResponse(
        submission_id=submission.id,
        mission_id=mission.id,
        place_id=mission.place_id,
        status=eval_status,
        ai_feedback=submission.ai_feedback,
        can_claim_reward=(eval_status == VerifyStatus.SUCCESS),
        submitted_at=submission.submitted_at
    )


@app.get("/api/v1/missions/submissions/{submission_id}", response_model=MissionVerifyResultResponse, tags=["4. AI 미션 및 인증 (S09-S11)"])
def get_mission_submission_result(
    submission_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[5.3.3 미션 인증 결과 단건 조회 / S11] 미션 인증 상태(성공·실패·오류·대기)와 거절 사유를 조회합니다."""
    sub = db.query(UserMission).filter(
        UserMission.id == submission_id,
        UserMission.user_id == current_user.id
    ).first()
    if not sub:
        raise HTTPException(status_code=404, detail="미션 인증 제출 내역을 찾을 수 없습니다.")

    return MissionVerifyResultResponse(
        submission_id=sub.id,
        mission_id=sub.mission_id,
        place_id=sub.place_id,
        status=VerifyStatus(sub.status),
        ai_feedback=sub.ai_feedback,
        can_claim_reward=(sub.status == VerifyStatus.SUCCESS.value),
        submitted_at=sub.submitted_at
    )


# ------------------------------------------
# [섹션 5] 보상 지급 및 확인 (명세 6.1 ~ 6.2 / 화면 S12, S13)
# ------------------------------------------
@app.post("/api/v1/rewards/claim", response_model=RewardResponse, tags=["5. 보상 지급 및 상세 (S12-S13)"])
def claim_reward(
    req: RewardClaimRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [6.1.1~6.1.2 보상 획득 및 지급 결과 확인 / S12]
    미션 인증이 승인(SUCCESS)된 건에 한해 보상을 지급하며, 미확정/실패 건은 거부하고 중복 지급을 방지합니다.
    """
    sub = db.query(UserMission).filter(
        UserMission.id == req.submission_id,
        UserMission.user_id == current_user.id
    ).first()
    if not sub:
        raise HTTPException(status_code=404, detail="미션 인증 내역을 찾을 수 없습니다.")

    if sub.status != VerifyStatus.SUCCESS.value:
        raise HTTPException(
            status_code=400,
            detail=f"미션 인증이 승인(SUCCESS)되지 않아 보상을 지급할 수 없습니다. (현재 상태: {sub.status})"
        )

    existing_reward = db.query(UserReward).filter(UserReward.user_mission_id == sub.id).first()
    if existing_reward:
        return RewardResponse(
            reward_id=existing_reward.id,
            place_id=existing_reward.place_id,
            place_name=existing_reward.place.name,
            reward_name=existing_reward.reward_name,
            reward_detail=existing_reward.reward_detail,
            quantity=existing_reward.quantity,
            issued_at=existing_reward.issued_at
        )

    mission = sub.mission
    reward = UserReward(
        user_id=current_user.id,
        user_mission_id=sub.id,
        place_id=sub.place_id,
        reward_name=mission.reward_name,
        reward_detail=mission.reward_detail,
        quantity=mission.reward_quantity
    )
    db.add(reward)
    db.commit()
    db.refresh(reward)

    return RewardResponse(
        reward_id=reward.id,
        place_id=reward.place_id,
        place_name=reward.place.name,
        reward_name=reward.reward_name,
        reward_detail=reward.reward_detail,
        quantity=reward.quantity,
        issued_at=reward.issued_at
    )

@app.post("/api/v1/files/upload", tags=["0. 공통 파일 업로드"])
def upload_file(
    file: UploadFile = File(..., description="업로드할 이미지 파일 (jpeg, png 등)"),
    current_user: User = Depends(get_current_user)
):
    """
    [멀티파트 이미지 업로드]
    프론트엔드에서 이미지를 업로드하면 서버 로컬에 저장하고, 접근 가능한 URL을 반환합니다.
    (추후 S3로 전환 시, 이 함수 내부 로직만 boto3 업로드로 변경하면 프론트엔드 수정 없이 대응 가능합니다.)
    """
    # 1. 확장자 추출 및 고유한 파일명(UUID) 생성 방지 (한글 파일명 깨짐 및 중복 방지)
    ext = file.filename.split(".")[-1] if "." in file.filename else "jpg"
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)

    # 2. 로컬 스토리지에 파일 저장
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 3. 클라이언트가 접근할 수 있는 정적 URL 반환
    # (운영 환경에서는 "http://localhost:8000" 부분을 실제 서버 도메인으로 변경해야 합니다)
    file_url = f"http://localhost:8000/uploads/{unique_filename}"

    return {
        "message": "파일 업로드 성공",
        "file_name": unique_filename,
        "file_url": file_url
    }


@app.get("/api/v1/rewards/{reward_id}", response_model=RewardResponse, tags=["5. 보상 지급 및 상세 (S12-S13)"])
def get_reward_detail(
    reward_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[6.2.1, 7.2.2 획득한 보상 상세 조회 / S13] 실제 지급이 완료된 보상의 상세 정보를 반환합니다."""
    reward = db.query(UserReward).filter(
        UserReward.id == reward_id,
        UserReward.user_id == current_user.id
    ).first()
    if not reward:
        raise HTTPException(status_code=404, detail="획득한 보상 내역을 찾을 수 없습니다.")

    return RewardResponse(
        reward_id=reward.id,
        place_id=reward.place_id,
        place_name=reward.place.name,
        reward_name=reward.reward_name,
        reward_detail=reward.reward_detail,
        quantity=reward.quantity,
        issued_at=reward.issued_at
    )


# ------------------------------------------
# [섹션 6] 마이페이지 (명세 7.1 ~ 7.3 / 화면 S14 ~ S19)
# ------------------------------------------
@app.get("/api/v1/mypage/summary", tags=["6. 마이페이지 (S14-S19)"])
def get_mypage_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[S14 마이페이지 메인] 계정 요약과 방문 장소 수, 획득 보상 수를 한 번에 반환합니다."""
    visit_count = db.query(PlaceVisit).filter(
        PlaceVisit.user_id == current_user.id,
        PlaceVisit.status == VerifyStatus.SUCCESS.value
    ).count()
    reward_count = db.query(UserReward).filter(UserReward.user_id == current_user.id).count()

    return {
        "user_id": current_user.id,
        "account_id": current_user.account_id,
        "nickname": current_user.nickname,
        "visited_place_count": visit_count,
        "total_reward_count": reward_count,
        "menus": ["방문 장소", "내 보상", "회원정보"]
    }


@app.get("/api/v1/mypage/visits", tags=["6. 마이페이지 (S14-S19)"])
def get_my_visited_places(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[7.1.1 방문 장소 목록 조회 / S15] 사용자가 방문 인증에 성공한 장소 목록을 조회하며, 기록이 없으면 안내 문구를 포함합니다."""
    visits = db.query(PlaceVisit).filter(
        PlaceVisit.user_id == current_user.id,
        PlaceVisit.status == VerifyStatus.SUCCESS.value
    ).order_by(PlaceVisit.verified_at.desc()).all()

    items = [
        {
            "visit_id": v.id,
            "place_id": v.place_id,
            "place_name": v.place.name,
            "address_summary": v.place.summary,
            "verified_at": v.verified_at
        }
        for v in visits
    ]
    return {
        "total_count": len(items),
        "is_empty": len(items) == 0,
        "empty_message": "아직 방문 인증한 장소가 없습니다. 지도에서 새로운 장소를 탐색해 보세요!" if len(items) == 0 else None,
        "visits": items
    }


@app.get("/api/v1/mypage/visits/{visit_id}", tags=["6. 마이페이지 (S14-S19)"])
def get_my_visited_place_detail(
    visit_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[7.1.2 방문 장소 상세 및 미션 내역 조회 / S16, 단디플로우] 선택한 방문 기록의 장소 상세 정보와 수행한 미션 내역을 함께 반환합니다."""
    visit = db.query(PlaceVisit).filter(
        PlaceVisit.id == visit_id,
        PlaceVisit.user_id == current_user.id
    ).first()
    if not visit:
        raise HTTPException(status_code=404, detail="방문 기록을 찾을 수 없습니다.")

    mission_history = db.query(UserMission).filter(
        UserMission.user_id == current_user.id,
        UserMission.place_id == visit.place_id
    ).order_by(UserMission.submitted_at.desc()).all()

    return {
        "visit_id": visit.id,
        "verified_at": visit.verified_at,
        "verify_method": visit.verify_method,
        "place": {
            "place_id": visit.place.id,
            "name": visit.place.name,
            "address": visit.place.address,
            "description": visit.place.description,
            "image_url": visit.place.image_url
        },
        "mission_histories": [
            {
                "submission_id": m.id,
                "mission_title": m.mission.title,
                "status": m.status,
                "proof_text": m.proof_text,
                "ai_feedback": m.ai_feedback,
                "submitted_at": m.submitted_at
            }
            for m in mission_history
        ]
    }


@app.get("/api/v1/mypage/rewards", tags=["6. 마이페이지 (S14-S19)"])
def get_my_rewards(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[7.2.1 내 보상 목록 조회 / S17] 사용자가 획득한 전체 보상 목록을 조회합니다."""
    rewards = db.query(UserReward).filter(
        UserReward.user_id == current_user.id
    ).order_by(UserReward.issued_at.desc()).all()

    items = [
        {
            "reward_id": r.id,
            "place_id": r.place_id,
            "place_name": r.place.name,
            "reward_name": r.reward_name,
            "reward_summary": r.reward_detail,
            "quantity": r.quantity,
            "issued_at": r.issued_at
        }
        for r in rewards
    ]
    return {
        "total_count": len(items),
        "is_empty": len(items) == 0,
        "empty_message": "아직 획득한 보상이 없습니다. 지도에서 미션을 탐색해 보세요!" if len(items) == 0 else None,
        "rewards": items
    }


@app.get("/api/v1/mypage/profile", tags=["6. 마이페이지 (S14-S19)"])
def get_my_profile(current_user: User = Depends(get_current_user)):
    """[7.3.1 회원정보 조회 / S18] 민감정보(비밀번호 해시)를 제외한 계정 정보와 닉네임을 반환합니다."""
    return {
        "user_id": current_user.id,
        "account_id": current_user.account_id,
        "nickname": current_user.nickname,
        "provider": current_user.provider,
        "extra_info": current_user.extra_info,
        "created_at": current_user.created_at
    }


@app.patch("/api/v1/mypage/profile", tags=["6. 마이페이지 (S14-S19)"])
def update_my_profile(
    req: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """[7.3.2 회원정보 수정 / S19] 수정 가능 항목(닉네임, 추가 정보)만 안전하게 편집하여 저장합니다."""
    if req.nickname is not None:
        current_user.nickname = req.nickname.strip()
    if req.extra_info is not None:
        current_user.extra_info = req.extra_info.strip()

    db.commit()
    db.refresh(current_user)
    return {
        "message": "회원정보 변경사항이 저장되었습니다.",
        "user_id": current_user.id,
        "account_id": current_user.account_id,
        "nickname": current_user.nickname,
        "extra_info": current_user.extra_info
    }