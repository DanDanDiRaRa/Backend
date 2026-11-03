"""API 명세서(Step 1~22) 기반 테스트. 실행: pip install pytest && pytest -v"""
import io
import json
import os
import tempfile

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

import main  # noqa: E402

A = {"latitude": 35.8680, "longitude": 128.5879}  # 장소 A 반경 내 (명세 Step 7)
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
    assert [p["pin_code"] for p in pins] == ["A", "B", "C"]
    assert pytest.approx(pins[0]["distance_meters"], abs=1) == 42.8
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


def test_photo_visit_requires_own_upload(client):
    h = auth(client)
    res = client.post("/api/v1/places/1/verify-visit", headers=h, json={
        "verify_method": "PHOTO", "photo_url": "https://example.com/anything.jpg"}).json()
    assert res["status"] == "ERROR"


def test_historical_photos_gate(client):
    h = auth(client)
    res = client.get("/api/v1/places/1/historical-photos", headers=h)
    assert res.status_code == 403
    assert res.json()["detail"] == "장소 방문 인증을 완료한 후에만 과거 사진을 열람할 수 있습니다."
    visit(client, h)
    assert client.get("/api/v1/places/1/historical-photos", headers=h).json()["has_photos"] is True


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
    assert [s.pin_code for s in main.load_place_seeds(main.PLACES_FILE)][:3] == ["A", "B", "C"]


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
