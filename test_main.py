"""API 명세서(Step 1~22) 기반 테스트. 실행: pip install pytest && pytest -v"""
import io
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace

_tmp = tempfile.mkdtemp()
os.chdir(_tmp)  # DB와 uploads를 임시 폴더에 생성
os.environ.update(
    APP_ENV="development",
    DATABASE_URL=f"sqlite:///{_tmp}/test.db",
    OPENAI_API_KEY="",
    OAUTH_DEMO_MODE="false",
    BASE_URL="http://testserver",
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Query  # noqa: E402

import main  # noqa: E402

A = {"latitude": 35.874004, "longitude": 128.578099}  # 장소 A 달성공원 좌표 (명세 Step 7)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
_counter = iter(range(1, 100000))


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:
        yield c


def auth(client):
    n = next(_counter)
    res = client.post("/api/v1/auth/signup", json={
        "account_id": f"user_{n}", "password": "password123!",
        "password_confirm": "password123!", "nickname": "골목기억수집가",
    })
    assert res.status_code == 201
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def visit(client, headers, place_id=1):
    res = client.post(f"/api/v1/places/{place_id}/verify-visit", headers=headers,
                      json={"verify_method": "GPS", **A})
    assert res.status_code == 200
    return res.json()


def mission(client, headers, place_id=1):
    visit(client, headers, place_id)
    res = client.post(f"/api/v1/places/{place_id}/missions/generate", headers=headers)
    assert res.status_code == 200
    return res.json()


# ---------- Step 1~4, 22: 인증 ----------
def test_signup_errors(client):
    body = {"account_id": "dup_user", "password": "password123!", "password_confirm": "other123!"}
    res = client.post("/api/v1/auth/signup", json=body)
    assert res.status_code == 400
    assert res.json()["detail"] == "비밀번호와 비밀번호 확인 입력값이 일치하지 않습니다."

    body["password_confirm"] = body["password"]
    assert client.post("/api/v1/auth/signup", json=body).status_code == 201
    res = client.post("/api/v1/auth/signup", json=body)
    assert res.status_code == 409
    assert res.json()["detail"] == "이미 사용 중인 계정입니다."


def test_login_failure_message(client):
    res = client.post("/api/v1/auth/login", json={"account_id": "nobody", "password": "wrong"})
    assert res.status_code == 401
    assert res.json()["detail"] == "입력 오류 또는 로그인 실패: 계정이나 비밀번호를 다시 확인해 주세요."


def test_missing_token_is_401(client):
    res = client.get("/api/v1/auth/status")
    assert res.status_code == 401
    assert res.json()["detail"] == "세션이 만료되었습니다. 재로그인해 주세요."


def test_status_and_logout(client):
    h = auth(client)
    body = client.get("/api/v1/auth/status", headers=h).json()
    assert body["is_Authenticated"] is True and body["provider"] == "LOCAL"
    assert "user_id" in client.post("/api/v1/auth/logout", headers=h).json()
    res = client.get("/api/v1/auth/status", headers=h)
    assert res.status_code == 401
    assert res.json()["detail"] == "로그아웃된 토큰입니다. 다시 로그인해 주세요."


def test_oauth_rejects_unverified_token(client, monkeypatch):
    monkeypatch.setattr(main.httpx, "get", lambda *a, **k: httpx.Response(401, json={}))
    res = client.post("/api/v1/auth/oauth", json={"provider": "KAKAO", "oauth_token": "fake"})
    assert res.status_code == 401


def test_oauth_kakao_id_is_stable_across_tokens(client, monkeypatch):
    monkeypatch.setattr(main.httpx, "get", lambda *a, **k: httpx.Response(200, json={"id": 987654321}))
    first = client.post("/api/v1/auth/oauth", json={"provider": "KAKAO", "oauth_token": "token-a"}).json()
    second = client.post("/api/v1/auth/oauth", json={"provider": "KAKAO", "oauth_token": "token-b"}).json()
    assert first["user_id"] == second["user_id"]
    assert first["account_id"] == "kakao_987654321"


def test_local_signup_cannot_take_social_namespace(client):
    res = client.post("/api/v1/auth/signup", json={
        "account_id": "kakao_987654321", "password": "password123!", "password_confirm": "password123!",
    })
    assert res.status_code == 400


@pytest.fixture
def same_second_login(client, monkeypatch):
    """모든 토큰이 같은 시각에 발급되도록 고정하고, 로그인할 때마다 새 헤더를 돌려줍니다."""
    now = main.utcnow()
    monkeypatch.setattr(main, "utcnow", lambda: now)
    cred = {"account_id": f"device_{next(_counter)}", "password": "password123!"}
    assert client.post("/api/v1/auth/signup", json={**cred, "password_confirm": cred["password"]}).status_code == 201

    def login():
        token = client.post("/api/v1/auth/login", json=cred).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    return login


def test_consecutive_logins_get_distinct_tokens(same_second_login):
    assert same_second_login() != same_second_login()


def test_logout_keeps_other_session(client, same_second_login):
    first, second = same_second_login(), same_second_login()
    client.post("/api/v1/auth/logout", headers=first)
    assert client.get("/api/v1/auth/status", headers=second).status_code == 200
    assert client.get("/api/v1/auth/status", headers=first).status_code == 401


def test_relogin_after_logout_works(client, same_second_login):
    old = same_second_login()
    client.post("/api/v1/auth/logout", headers=old)
    assert client.get("/api/v1/auth/status", headers=same_second_login()).status_code == 200
    assert client.get("/api/v1/auth/status", headers=old).status_code == 401


# ---------- Step 5~8: 지도, 방문 인증, 과거 사진 ----------
def test_recommendations_match_spec_distances(client):
    pins = client.get("/api/v1/places/recommendations",
                      params={"latitude": 35.8682, "longitude": 128.5875}).json()
    assert [p["pin_code"] for p in pins] == ["B", "E", "A", "C", "D"]
    assert pytest.approx(pins[0]["distance_meters"], abs=1) == 609.0
    no_location = client.get("/api/v1/places/recommendations").json()
    assert all(p["distance_meters"] is None for p in no_location)


def test_verify_visit_cases(client):
    h = auth(client)
    ok = visit(client, h)
    assert ok["status"] == "SUCCESS" and ok["can_view_historical_photos"] is True
    assert ok["verified_at"].endswith(("Z", "+00:00"))  # 시간대 포함

    far = client.post("/api/v1/places/1/verify-visit", headers=h, json={
        "verify_method": "GPS", "latitude": 35.85, "longitude": 128.55}).json()
    assert far["status"] == "FAILED"

    none = client.post("/api/v1/places/1/verify-visit", headers=h, json={
        "verify_method": "GPS", "latitude": None, "longitude": None}).json()
    assert none["status"] == "ERROR"


def test_qr_visit_method_is_rejected(client):
    res = client.post("/api/v1/places/1/verify-visit", headers=auth(client),
                      json={"verify_method": "QR", "qr_code": "anything"})
    assert res.status_code == 422


# ---------- 사진 방문 인증 (GPS 인증 실패 후에만 허용) ----------
PHOTO_GATE_REASON = "GPS 인증에 실패한 경우에만 사진 인증을 사용할 수 있습니다. 먼저 GPS 인증을 시도해 주세요."
FAR = {"latitude": 35.85, "longitude": 128.55}  # 장소 A·B에서 3km 이상 떨어진 좌표
NO_LOCATION = {"latitude": None, "longitude": None}


def gps_attempt(client, headers, coords, place_id=1):
    res = client.post(f"/api/v1/places/{place_id}/verify-visit", headers=headers,
                      json={"verify_method": "GPS", **coords})
    assert res.status_code == 200
    return res.json()


def photo_attempt(client, headers, photo_url, place_id=1):
    res = client.post(f"/api/v1/places/{place_id}/verify-visit", headers=headers,
                      json={"verify_method": "PHOTO", "photo_url": photo_url})
    assert res.status_code == 200
    return res.json()


def upload_png(client, headers):
    res = client.post("/api/v1/files/upload", headers=headers, files={"file": ("x.png", io.BytesIO(PNG), "image/png")})
    assert res.status_code == 200
    return res.json()["file_url"]


@pytest.fixture
def vision(monkeypatch):
    """사진 심사 AI 호출 수와 업로드 이미지 읽기 수를 기록합니다. verdicts에 넣은 순서대로 판정합니다."""
    spy = SimpleNamespace(ai_calls=0, image_reads=0, verdicts=[])
    resolve = main._resolve_image_for_vision

    def tracked_resolve(url):
        spy.image_reads += 1
        return resolve(url)

    def create(**kwargs):
        spy.ai_calls += 1
        verdict = spy.verdicts.pop(0) if spy.verdicts else "SUCCESS"
        content = json.dumps({"status": verdict, "reason": f"테스트 판정: {verdict}"})
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])

    monkeypatch.setattr(main, "_resolve_image_for_vision", tracked_resolve)
    monkeypatch.setattr(main, "openai_client", SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    return spy


def assert_photo_gated(res, vision):
    assert res["status"] == "ERROR" and res["reason"] == PHOTO_GATE_REASON
    assert res["can_view_historical_photos"] is False
    assert vision.ai_calls == 0 and vision.image_reads == 0  # 사진 URL 검사와 AI 호출 없음


def test_photo_visit_requires_own_upload(client, vision):
    h = auth(client)
    assert gps_attempt(client, h, FAR)["status"] == "FAILED"
    res = photo_attempt(client, h, "https://example.com/anything.jpg")
    assert res["status"] == "ERROR"
    assert res["reason"] == "업로드한 방문 인증 사진을 찾을 수 없습니다. 사진을 다시 업로드해 주세요."
    assert vision.ai_calls == 0


def test_photo_after_gps_failure_keeps_existing_error_handling(client, vision, monkeypatch):
    h = auth(client)
    gps_attempt(client, h, FAR)

    missing = client.post("/api/v1/places/1/verify-visit", headers=h, json={"verify_method": "PHOTO"}).json()
    assert missing["status"] == "ERROR" and missing["reason"] == "방문 인증 사진이 정상적으로 첨부되지 않았습니다."

    def broken(**kwargs):
        raise RuntimeError("vision unavailable")

    monkeypatch.setattr(main.openai_client.chat.completions, "create", broken)
    failed = photo_attempt(client, h, upload_png(client, h))
    assert failed["status"] == "ERROR"
    assert failed["reason"] == "사진 심사 중 일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요."


def test_photo_rejected_without_gps_attempt(client, vision):
    h = auth(client)
    assert_photo_gated(photo_attempt(client, h, upload_png(client, h)), vision)


def test_photo_rejected_when_only_gps_success(client, vision):
    h = auth(client)
    assert gps_attempt(client, h, A)["status"] == "SUCCESS"
    assert_photo_gated(photo_attempt(client, h, upload_png(client, h)), vision)


@pytest.mark.parametrize("coords, gps_status", [(FAR, "FAILED"), (NO_LOCATION, "ERROR")])
def test_photo_allowed_after_gps_failure(client, vision, coords, gps_status):
    h = auth(client)
    assert gps_attempt(client, h, coords)["status"] == gps_status
    res = photo_attempt(client, h, upload_png(client, h))
    assert res["status"] == "SUCCESS" and res["can_view_historical_photos"] is True
    assert vision.ai_calls == 1


def test_gps_failure_at_other_place_not_counted(client, vision):
    h = auth(client)
    assert gps_attempt(client, h, FAR, place_id=2)["status"] == "FAILED"
    assert_photo_gated(photo_attempt(client, h, upload_png(client, h), place_id=1), vision)


def test_other_users_gps_failure_not_counted(client, vision):
    other = auth(client)
    assert gps_attempt(client, other, FAR)["status"] == "FAILED"
    h = auth(client)
    assert_photo_gated(photo_attempt(client, h, upload_png(client, h)), vision)


def test_photo_failures_alone_do_not_unlock_photo(client, vision):
    h = auth(client)
    user_id = client.get("/api/v1/auth/status", headers=h).json()["user_id"]
    db = main.SessionLocal()
    try:
        db.add_all(main.PlaceVisit(user_id=user_id, place_id=1, verify_method="PHOTO", status=status,
                                   reason="이전 사진 인증 실패") for status in ("FAILED", "ERROR"))
        db.commit()
    finally:
        db.close()
    assert_photo_gated(photo_attempt(client, h, upload_png(client, h)), vision)


def test_photo_can_retry_after_photo_failure(client, vision):
    h = auth(client)
    gps_attempt(client, h, FAR)
    vision.verdicts = ["FAILED", "SUCCESS"]
    assert photo_attempt(client, h, upload_png(client, h))["status"] == "FAILED"
    retry = photo_attempt(client, h, upload_png(client, h))
    assert retry["status"] == "SUCCESS" and retry["can_view_historical_photos"] is True
    assert vision.ai_calls == 2


def test_historical_photos_gate(client):
    h = auth(client)
    res = client.get("/api/v1/places/1/historical-photos", headers=h)
    assert res.status_code == 403
    assert res.json()["detail"] == "장소 방문 인증을 완료한 후에만 과거 사진을 열람할 수 있습니다."
    visit(client, h)
    assert client.get("/api/v1/places/1/historical-photos", headers=h).json()["has_photos"] is True


# ---------- 장소 사진과 출처 ----------
def place_id_by_pin(client, pin):
    return next(p["id"] for p in client.get("/api/v1/places/recommendations").json() if p["pin_code"] == pin)


def test_place_detail_returns_absolute_static_image_and_source(client):
    body = client.get(f"/api/v1/places/{place_id_by_pin(client, 'A')}", headers=auth(client)).json()
    assert body["image_url"] == "http://testserver/static/places/dalseong-main.jpg"
    assert body["image_source"].startswith("출처 - 대구광역시")
    res = client.get("/static/places/dalseong-main.jpg")
    assert res.status_code == 200 and res.headers["content-type"] == "image/jpeg"


def test_place_without_image_returns_null(client):
    body = client.get(f"/api/v1/places/{place_id_by_pin(client, 'C')}", headers=auth(client)).json()
    assert body["name"] == "대구역"
    assert body["image_url"] is None and body["image_source"] is None


def test_historical_photos_and_visit_detail_use_absolute_urls(client):
    h = auth(client)
    visit_id = visit(client, h)["visit_id"]
    photos = client.get("/api/v1/places/1/historical-photos", headers=h).json()["photos"]
    assert len(photos) == 4
    assert all(p["image_url"].startswith("http://testserver/static/places/") for p in photos)
    place = client.get(f"/api/v1/mypage/visits/{visit_id}", headers=h).json()["place"]
    assert place["image_url"] == "http://testserver/static/places/dalseong-main.jpg"
    assert place["image_source"].startswith("출처 - 대구광역시")


def test_mission_prompt_sends_text_only(client, monkeypatch):
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))])

    fake = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(main, "openai_client", fake)
    db = main.SessionLocal()
    try:
        place = db.query(main.Place).filter_by(pin_code="A").one()
        _, is_ai = main.generate_ai_mission_for_place(place, place.historical_photos)
    finally:
        db.close()

    assert is_ai is True
    assert all(isinstance(m["content"], str) for m in captured["messages"])  # 이미지 입력 없음
    prompt = "\n".join(m["content"] for m in captured["messages"])
    assert "/static/" not in prompt and ".jpg" not in prompt
    assert "1971년" in prompt  # 과거 사진의 텍스트 정보는 전달


# ---------- Step 9~12: 미션 ----------
def test_mission_shape_and_no_false_ai_flag(client):
    body = mission(client, auth(client))
    assert len(body["step_guides"]) == 3
    assert body["created_by_ai"] is False  # API 키가 없으면 AI 생성으로 표시하지 않음


def test_upload_accepts_image_rejects_html(client):
    h = auth(client)
    bad = client.post("/api/v1/files/upload", headers=h,
                      files={"file": ("x.jpg", io.BytesIO(b"<script>alert(1)</script>"), "image/jpeg")})
    assert bad.status_code == 400
    good = client.post("/api/v1/files/upload", headers=h, files={"file": ("x.html", io.BytesIO(PNG), "text/html")})
    assert good.status_code == 200
    assert good.json()["file_name"].endswith(".png")
    assert good.json()["file_url"].startswith("http://testserver/uploads/")


def test_upload_size_limit(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 16)
    res = client.post("/api/v1/files/upload", headers=auth(client),
                      files={"file": ("x.png", io.BytesIO(PNG), "image/png")})
    assert res.status_code == 413


def test_submit_requires_visit(client):
    mission_id = mission(client, auth(client))["mission_id"]
    res = client.post(f"/api/v1/missions/{mission_id}/submit", headers=auth(client),
                      json={"proof_text": "방문하지 않고 제출하는 충분히 긴 기록입니다."})
    assert res.status_code == 403


@pytest.mark.parametrize("url", [
    "http://x/uploads/../memory_coordinates.db",
    "http://x/uploads/../../etc/passwd",
    "https://example.com/photo.jpg",
])
def test_submit_rejects_foreign_image(client, url):
    h = auth(client)
    mission_id = mission(client, h)["mission_id"]
    res = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h, json={"proof_image_url": url})
    assert res.status_code == 400


def test_full_mission_reward_flow(client):
    h = auth(client)
    mission_id = mission(client, h)["mission_id"]

    fail = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h, json={"proof_text": "짧음"}).json()
    assert fail["status"] == "FAILED" and fail["can_claim_reward"] is False
    res = client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": fail["submission_id"]})
    assert res.status_code == 400
    assert res.json()["detail"] == "미션 인증이 승인(SUCCESS)되지 않아 보상을 지급할 수 없습니다. (현재 상태: FAILED)"

    ok = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h,
                     json={"proof_text": "첨탑은 그대로지만 주변 기와집은 사라졌습니다."}).json()
    assert ok["status"] == "SUCCESS" and ok["can_claim_reward"] is True

    dup = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h,
                      json={"proof_text": "한 번 더 제출하는 충분히 긴 기록입니다."})
    assert dup.status_code == 409
    assert dup.json()["detail"] == "이미 인증이 완료된 미션입니다. 중복 제출할 수 없습니다."

    fetched = client.get(f"/api/v1/missions/submissions/{ok['submission_id']}", headers=h).json()
    assert fetched["status"] == "SUCCESS"

    reward = client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": ok["submission_id"]}).json()
    assert reward["issued_status"] == "COMPLETED"
    again = client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": ok["submission_id"]}).json()
    assert again["reward_id"] == reward["reward_id"]  # 중복 지급 없음
    assert client.get(f"/api/v1/rewards/{reward['reward_id']}", headers=h).status_code == 200

    # Step 18~19
    visits = client.get("/api/v1/mypage/visits", headers=h).json()
    detail = client.get(f"/api/v1/mypage/visits/{visits['visits'][0]['visit_id']}", headers=h).json()
    assert [m["status"] for m in detail["mission_histories"]] == ["SUCCESS", "FAILED"]
    assert client.get("/api/v1/mypage/rewards", headers=h).json()["total_count"] == 1


def test_other_user_cannot_read_submission(client):
    h = auth(client)
    mission_id = mission(client, h)["mission_id"]
    sub = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h, json={"proof_text": "짧음"}).json()
    res = client.get(f"/api/v1/missions/submissions/{sub['submission_id']}", headers=auth(client))
    assert res.status_code == 404


# ---------- 내 미션 제출 내역 목록 ----------
MY_SUBMISSIONS = "/api/v1/missions/my-submissions"
LONG_PROOF = "첨탑은 그대로지만 주변 기와집은 사라졌습니다."


def mission_at(client, headers, place_id):
    """해당 장소 좌표로 GPS 방문 인증을 마치고 그 장소의 미션을 받습니다."""
    place = next(p for p in client.get("/api/v1/places/recommendations").json() if p["id"] == place_id)
    res = client.post(f"/api/v1/places/{place_id}/verify-visit", headers=headers, json={
        "verify_method": "GPS", "latitude": place["latitude"], "longitude": place["longitude"]})
    assert res.json()["status"] == "SUCCESS"
    res = client.post(f"/api/v1/places/{place_id}/missions/generate", headers=headers)
    assert res.status_code == 200
    return res.json()


def submit(client, headers, mission_id, proof_text):
    res = client.post(f"/api/v1/missions/{mission_id}/submit", headers=headers, json={"proof_text": proof_text})
    assert res.status_code == 200
    return res.json()


def my_submissions(client, headers, **params):
    res = client.get(MY_SUBMISSIONS, headers=headers, params=params)
    assert res.status_code == 200
    return res.json()


@pytest.mark.parametrize("headers, detail", [
    ({}, "세션이 만료되었습니다. 재로그인해 주세요."),
    ({"Authorization": "Bearer not-a-jwt"}, "세션이 만료되었습니다. 재로그인해 주세요."),
])
def test_my_submissions_requires_login(client, headers, detail):
    res = client.get(MY_SUBMISSIONS, headers=headers)
    assert res.status_code == 401
    assert res.json()["detail"] == detail


def test_my_submissions_empty(client):
    assert my_submissions(client, auth(client)) == {"total_count": 0, "submissions": []}


def test_my_submissions_newest_first_and_matches_single_lookup(client):
    h = auth(client)
    m1 = mission_at(client, h, 1)["mission_id"]
    m2 = mission_at(client, h, 2)["mission_id"]
    first = submit(client, h, m1, "짧음")
    second = submit(client, h, m1, LONG_PROOF)
    third = submit(client, h, m2, "짧음")

    body = my_submissions(client, h)
    assert body["total_count"] == 3
    assert [s["submission_id"] for s in body["submissions"]] == \
        [third["submission_id"], second["submission_id"], first["submission_id"]]

    # 기존 단건 조회 API와 같은 값·시간 형식, reward_id만 추가
    for item in body["submissions"]:
        single = client.get(f"/api/v1/missions/submissions/{item['submission_id']}", headers=h).json()
        assert {k: v for k, v in item.items() if k != "reward_id"} == single
        assert item["reward_id"] is None
        assert item["submitted_at"].endswith(("Z", "+00:00"))
    assert [s["can_claim_reward"] for s in body["submissions"]] == [False, True, False]

    # id 순서가 아니라 제출 시각 기준으로 정렬하는지 확인
    db = main.SessionLocal()
    try:
        sub = db.get(main.UserMission, first["submission_id"])
        sub.submitted_at = main.utcnow() + main.timedelta(hours=1)
        db.commit()
    finally:
        db.close()
    assert my_submissions(client, h)["submissions"][0]["submission_id"] == first["submission_id"]


def test_my_submissions_place_filter(client):
    h = auth(client)
    m1 = mission_at(client, h, 1)["mission_id"]
    m2 = mission_at(client, h, 2)["mission_id"]
    at_place1 = submit(client, h, m1, "짧음")
    at_place2 = [submit(client, h, m2, "짧음"), submit(client, h, m2, LONG_PROOF)]

    body = my_submissions(client, h, place_id=2)
    assert body["total_count"] == 2
    assert [s["submission_id"] for s in body["submissions"]] == [s["submission_id"] for s in reversed(at_place2)]
    assert all(s["place_id"] == 2 for s in body["submissions"])

    body = my_submissions(client, h, place_id=1)
    assert [s["submission_id"] for s in body["submissions"]] == [at_place1["submission_id"]]

    # 제출이 없는 실제 장소는 404가 아니라 빈 목록
    assert my_submissions(client, h, place_id=3) == {"total_count": 0, "submissions": []}


def test_my_submissions_unknown_place_is_404(client):
    res = client.get(MY_SUBMISSIONS, headers=auth(client), params={"place_id": 99999})
    assert res.status_code == 404
    assert res.json()["detail"] == "장소를 찾을 수 없습니다."


def test_my_submissions_hides_other_users(client):
    other = auth(client)
    other_sub = submit(client, other, mission_at(client, other, 1)["mission_id"], LONG_PROOF)
    h = auth(client)
    mine = submit(client, h, mission_at(client, h, 1)["mission_id"], "짧음")

    for params in ({}, {"place_id": 1}):
        ids = [s["submission_id"] for s in my_submissions(client, h, **params)["submissions"]]
        assert ids == [mine["submission_id"]]
    assert [s["submission_id"] for s in my_submissions(client, other)["submissions"]] == [other_sub["submission_id"]]


def test_my_submissions_reward_id_after_claim(client):
    h = auth(client)
    mission_id = mission_at(client, h, 1)["mission_id"]
    fail = submit(client, h, mission_id, "짧음")
    ok = submit(client, h, mission_id, LONG_PROOF)

    before = {s["submission_id"]: s for s in my_submissions(client, h)["submissions"]}
    assert before[ok["submission_id"]]["reward_id"] is None
    assert before[ok["submission_id"]]["can_claim_reward"] is True

    reward = client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": ok["submission_id"]}).json()
    after = {s["submission_id"]: s for s in my_submissions(client, h)["submissions"]}
    assert after[ok["submission_id"]]["reward_id"] == reward["reward_id"]
    assert after[ok["submission_id"]]["can_claim_reward"] is True  # 기존 제출 API와 같은 기준 (SUCCESS 여부)
    assert after[fail["submission_id"]]["reward_id"] is None
    assert len(after) == 2  # 보상 조인으로 행이 늘어나지 않음


def test_my_submissions_route_does_not_shadow_single_lookup(client):
    h = auth(client)
    sub = submit(client, h, mission_at(client, h, 1)["mission_id"], "짧음")
    single = client.get(f"/api/v1/missions/submissions/{sub['submission_id']}", headers=h)
    assert single.status_code == 200 and "reward_id" not in single.json()
    assert client.get("/api/v1/missions/submissions/my-submissions", headers=h).status_code == 422
    assert "submissions" in my_submissions(client, h)


# ---------- 개발용 미션 초기화 API ----------
RESET = "/api/v1/dev/missions/reset"
DEV_TOKEN = "test-dev-token"


@pytest.fixture
def dev_token(monkeypatch):
    monkeypatch.setattr(main, "DEV_RESET_TOKEN", DEV_TOKEN)
    return {"X-Dev-Token": DEV_TOKEN}


def reset(client, headers, token_headers, **params):
    return client.post(RESET, headers={**headers, **token_headers}, params=params)


def make_records(client, headers):
    """장소 1에 실패 1·승인 1, 장소 2에 승인 1을 제출하고 승인 건의 보상을 받습니다. (제출 3개, 보상 2개)"""
    m1 = mission_at(client, headers, 1)["mission_id"]
    m2 = mission_at(client, headers, 2)["mission_id"]
    fail1 = submit(client, headers, m1, "짧음")
    ok1 = submit(client, headers, m1, LONG_PROOF)
    ok2 = submit(client, headers, m2, LONG_PROOF)
    rewards = [
        client.post("/api/v1/rewards/claim", headers=headers, json={"submission_id": s["submission_id"]}).json()["reward_id"]
        for s in (ok1, ok2)
    ]
    return {"missions": (m1, m2), "subs": (fail1["submission_id"], ok1["submission_id"], ok2["submission_id"]),
            "rewards": rewards}


def reward_count(client, headers):
    return client.get("/api/v1/mypage/rewards", headers=headers).json()["total_count"]


def test_reset_is_404_when_token_not_configured(client, monkeypatch):
    monkeypatch.setattr(main, "DEV_RESET_TOKEN", "")
    h = auth(client)
    for headers in ({}, {"X-Dev-Token": ""}, {"X-Dev-Token": "anything"}):
        res = client.post(RESET, headers={**h, **headers})
        assert res.status_code == 404 and res.json() == {"detail": "Not Found"}
    assert client.post(RESET).status_code == 404  # 로그인 없이도 API 존재를 드러내지 않음


def test_reset_requires_matching_dev_token(client, dev_token):
    h = auth(client)
    submit(client, h, mission_at(client, h, 1)["mission_id"], "짧음")
    for headers in (
        {}, {"X-Dev-Token": ""}, {"X-Dev-Token": "wrong"}, {"X-Dev-Token": DEV_TOKEN + "x"},
        {"X-Dev-Token": DEV_TOKEN[:-1]}, {"X-Dev-Token": "한글토큰".encode("utf-8")},  # ASCII 아닌 값도 500이 아닌 403
    ):
        res = client.post(RESET, headers={**h, **headers})
        assert res.status_code == 403, headers
    assert my_submissions(client, h)["total_count"] == 1  # 거절된 요청은 아무것도 지우지 않음


def test_reset_requires_login(client, dev_token):
    for headers in ({}, {"Authorization": "Bearer not-a-jwt"}):
        res = client.post(RESET, headers={**headers, **dev_token})
        assert res.status_code == 401
        assert res.json()["detail"] == "세션이 만료되었습니다. 재로그인해 주세요."
    assert client.post(RESET).status_code == 403  # 토큰 검사가 먼저 실행됨


def test_reset_is_hidden_from_docs(client):
    assert any(getattr(r, "path", "") == RESET for r in main.app.routes)  # 등록은 되어 있음
    assert RESET not in client.get("/openapi.json").json()["paths"]


def test_reset_route_is_not_registered_in_production(tmp_path):
    repo = os.path.dirname(os.path.abspath(main.__file__))
    script = ("import sys; sys.path.insert(0, sys.argv[1]); import main; "
              f"print(any(getattr(r, 'path', '') == '{RESET}' for r in main.app.routes))")

    def registered(**env):
        full_env = {**os.environ, "DEV_RESET_TOKEN": "token-set-even-in-production", "PYTHONDONTWRITEBYTECODE": "1",
                    "DATABASE_URL": f"sqlite:///{tmp_path}/{env['APP_ENV']}.db", **env}
        done = subprocess.run([sys.executable, "-c", script, repo], cwd=tmp_path, env=full_env,
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr
        return done.stdout.strip() == "True"

    assert registered(APP_ENV="development") is True  # 대조군: 개발 모드에서는 등록됨
    assert registered(APP_ENV="production", JWT_SECRET_KEY="test-secret-for-subprocess", OPENAI_API_KEY="test-key",
                      BASE_URL="https://api.test", CORS_ORIGINS="https://front.test", OAUTH_DEMO_MODE="false") is False


def test_reset_by_place_keeps_other_places_and_users(client, dev_token):
    other = auth(client)
    other_rec = make_records(client, other)
    h = auth(client)
    rec = make_records(client, h)

    res = reset(client, h, dev_token, place_id=1)
    assert res.status_code == 200
    assert res.json() == {"deleted_submissions": 2, "deleted_rewards": 1}

    mine = my_submissions(client, h)["submissions"]
    assert [s["submission_id"] for s in mine] == [rec["subs"][2]]  # 장소 2의 제출만 남음
    assert mine[0]["reward_id"] == rec["rewards"][1]
    assert reward_count(client, h) == 1
    assert client.get(f"/api/v1/rewards/{rec['rewards'][0]}", headers=h).status_code == 404  # 장소 1의 보상은 함께 삭제
    assert client.get(f"/api/v1/rewards/{rec['rewards'][1]}", headers=h).status_code == 200

    # 방문 기록과 미션은 남음
    assert client.get("/api/v1/mypage/visits", headers=h).json()["total_count"] == 2
    assert client.post("/api/v1/places/1/missions/generate", headers=h).json()["mission_id"] == rec["missions"][0]

    # 다른 사용자의 기록은 그대로
    theirs = my_submissions(client, other)["submissions"]
    assert len(theirs) == 3
    assert sorted(s["reward_id"] for s in theirs if s["reward_id"]) == sorted(other_rec["rewards"])
    assert reward_count(client, other) == 2


def test_reset_all_keeps_visits_and_other_users(client, dev_token):
    other = auth(client)
    make_records(client, other)
    h = auth(client)
    make_records(client, h)

    assert reset(client, h, dev_token).json() == {"deleted_submissions": 3, "deleted_rewards": 2}
    assert my_submissions(client, h) == {"total_count": 0, "submissions": []}
    assert reward_count(client, h) == 0
    assert client.get("/api/v1/mypage/visits", headers=h).json()["total_count"] == 2
    assert my_submissions(client, other)["total_count"] == 3
    assert reward_count(client, other) == 2
    assert reset(client, h, dev_token).json() == {"deleted_submissions": 0, "deleted_rewards": 0}


def test_can_resubmit_same_mission_after_reset(client, dev_token):
    h = auth(client)
    mission_id = mission_at(client, h, 1)["mission_id"]
    first = submit(client, h, mission_id, LONG_PROOF)
    client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": first["submission_id"]})
    dup = client.post(f"/api/v1/missions/{mission_id}/submit", headers=h, json={"proof_text": LONG_PROOF})
    assert dup.status_code == 409  # 초기화 전에는 중복 제출 불가

    assert reset(client, h, dev_token).json() == {"deleted_submissions": 1, "deleted_rewards": 1}
    again = submit(client, h, mission_id, LONG_PROOF)
    assert again["status"] == "SUCCESS" and again["can_claim_reward"] is True
    claim = client.post("/api/v1/rewards/claim", headers=h, json={"submission_id": again["submission_id"]})
    assert claim.status_code == 200
    assert client.get("/api/v1/mypage/summary", headers=h).json()["total_reward_count"] == 1


def test_reset_unknown_place_is_404_and_deletes_nothing(client, dev_token):
    h = auth(client)
    submit(client, h, mission_at(client, h, 1)["mission_id"], "짧음")
    res = reset(client, h, dev_token, place_id=99999)
    assert res.status_code == 404 and res.json()["detail"] == "장소를 찾을 수 없습니다."
    assert my_submissions(client, h)["total_count"] == 1


def test_reset_is_one_transaction(client, dev_token, monkeypatch):
    h = auth(client)
    make_records(client, h)
    real_delete = Query.delete
    calls = []

    def flaky_delete(self, *args, **kwargs):
        calls.append(1)
        if len(calls) == 2:  # 보상 삭제 뒤, 제출 삭제에서 실패
            raise RuntimeError("simulated failure while deleting submissions")
        return real_delete(self, *args, **kwargs)

    monkeypatch.setattr(Query, "delete", flaky_delete)
    with pytest.raises(RuntimeError):
        reset(client, h, dev_token)
    monkeypatch.setattr(Query, "delete", real_delete)

    assert len(calls) == 2  # 보상 삭제가 이미 실행된 뒤에 실패했음
    assert my_submissions(client, h)["total_count"] == 3
    assert reward_count(client, h) == 2  # 보상 삭제도 함께 되돌려짐


# ---------- Step 16~21: 마이페이지 ----------
def test_mypage_counts_places_not_attempts(client):
    h = auth(client)
    first = visit(client, h)
    latest = visit(client, h)
    assert client.get("/api/v1/mypage/summary", headers=h).json()["visited_place_count"] == 1
    listing = client.get("/api/v1/mypage/visits", headers=h).json()
    assert listing["total_count"] == 1
    assert listing["visits"][0]["visit_id"] == latest["visit_id"] != first["visit_id"]


def test_failed_visit_detail_hidden(client):
    h = auth(client)
    failed = client.post("/api/v1/places/1/verify-visit", headers=h, json={
        "verify_method": "GPS", "latitude": 35.85, "longitude": 128.55}).json()
    assert client.get(f"/api/v1/mypage/visits/{failed['visit_id']}", headers=h).status_code == 404


def test_mypage_empty_states_and_profile(client):
    h = auth(client)
    assert client.get("/api/v1/mypage/visits", headers=h).json()["empty_message"] == \
        "아직 방문 인증한 장소가 없습니다. 지도에서 새로운 장소를 탐색해 보세요!"
    assert client.get("/api/v1/mypage/rewards", headers=h).json()["empty_message"] == \
        "아직 획득한 보상이 없습니다. 지도에서 미션을 탐색해 보세요!"
    updated = client.patch("/api/v1/mypage/profile", headers=h,
                           json={"nickname": "대구근대골목마스터", "extra_info": "참여자"}).json()
    assert updated["message"] == "회원정보 변경사항이 저장되었습니다."
    profile = client.get("/api/v1/mypage/profile", headers=h).json()
    assert profile["nickname"] == "대구근대골목마스터" and "password_hash" not in profile


# ---------- 장소 파일 ----------
def _seed(**overrides):
    return {**{
        "pin_code": "Z", "name": "테스트 장소", "address": "대구광역시 중구", "summary": "요약",
        "description": "설명", "latitude": 35.87, "longitude": 128.59,
        "historical_photos": [{"image_url": "https://x/a.jpg", "taken_year": "1950년", "source": "테스트 출처"}],
    }, **overrides}


def _write(tmp_path, data):
    path = tmp_path / "places.json"
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return str(path)


def test_places_file_is_valid():
    assert [s.pin_code for s in main.load_place_seeds(main.PLACES_FILE)] == ["A", "B", "C", "D", "E"]


def test_sync_adds_and_updates_without_changing_ids(client, tmp_path):
    db = main.SessionLocal()
    try:
        place_a_id = db.query(main.Place).filter_by(pin_code="A").one().id
        seeds = main.load_place_seeds(_write(tmp_path, [
            _seed(pin_code="A", name="이름 변경", historical_photos=[]),
            _seed(),
        ]))
        main.sync_places(db, seeds)

        place_a = db.query(main.Place).filter_by(pin_code="A").one()
        assert place_a.id == place_a_id and place_a.name == "이름 변경"
        assert db.query(main.HistoricalPhoto).filter_by(place_id=place_a_id).count() == 0

        place_z = db.query(main.Place).filter_by(pin_code="Z").one()
        assert db.query(main.HistoricalPhoto).filter_by(place_id=place_z.id).count() == 1
        assert db.query(main.Place).filter_by(pin_code="B").count() == 1  # 파일에서 빠져도 삭제하지 않음
    finally:
        db.rollback()  # 다른 테스트에 영향이 없도록 되돌림
        db.close()


@pytest.mark.parametrize("data", [
    [],
    [_seed(latitude=128.59, longitude=35.87)],  # 위도·경도 뒤바뀜
    [_seed(), _seed()],  # pin_code 중복
    [{"pin_code": "Z"}],  # 필수 항목 누락
])
def test_invalid_places_file_is_rejected(tmp_path, data):
    with pytest.raises(RuntimeError):
        main.load_place_seeds(_write(tmp_path, data))


def test_every_static_image_in_places_file_exists():
    seeds = main.load_place_seeds(main.PLACES_FILE)
    urls = [s.image_url for s in seeds] + [p.image_url for s in seeds for p in s.historical_photos]
    static_urls = [u for u in urls if u and u.startswith("/static/")]
    assert len(static_urls) == 19
    missing = [u for u in static_urls if not os.path.isfile(os.path.join(main.STATIC_DIR, u[len("/static/"):]))]
    assert missing == []


@pytest.mark.parametrize("overrides", [
    {"image_url": "https://example.com/main.jpg"},
    {"historical_photos": [{"image_url": "https://cdn.example.com/a.jpg", "taken_year": "1950년", "source": "테스트 출처"}]},
    {"historical_photos": [{"image_url": "/static/a.jpg", "taken_year": "1950년", "source": "샘플 데이터 - 실제 출처 확인 전"}]},
    {"image_source": "샘플 데이터"},
])
def test_production_rejects_sample_place_data(tmp_path, monkeypatch, overrides):
    path = _write(tmp_path, [_seed(**overrides)])
    assert main.load_place_seeds(path)  # 개발 모드에서는 허용
    monkeypatch.setattr(main, "IS_PRODUCTION", True)
    with pytest.raises(RuntimeError, match="샘플 장소 데이터"):
        main.load_place_seeds(path)


def test_production_accepts_real_places_file(monkeypatch):
    monkeypatch.setattr(main, "IS_PRODUCTION", True)
    assert len(main.load_place_seeds(main.PLACES_FILE)) == 5
