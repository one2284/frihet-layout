#!/usr/bin/env python3
"""
프리헷 물류 배치도 서버 (파이썬 기본 라이브러리만 사용, 별도 설치 불필요)

- 누구나:    배치도 조회 (GET /, GET /api/layout)
- 관리자만:  저장 (PUT /api/layout)  ← 비밀번호는 서버에만 보관

실행:
    python3 server.py
    (FND 같은 배포 도구에서는 Dockerfile 로 자동 실행됩니다)

설정(환경변수, 모두 선택 사항):
    PORT                   서버 포트 (기본 8080)
    FRIHET_ADMIN_PASSWORD  관리자 비밀번호. 지정하지 않으면 기본 비밀번호 사용
    FRIHET_DATA_DIR        재고 데이터 저장 폴더 (기본 ./data)
                           → 재배포해도 데이터가 남도록 이 폴더는 영구 저장소(볼륨)에 연결하세요

데이터는 data/layout.json 에 저장되고, 저장할 때마다 data/backups/ 에
이전 버전이 최근 200개까지 남습니다. data 폴더가 비어 있으면
저장소에 함께 있는 layout.json 을 처음 내용으로 사용합니다.
"""
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("FRIHET_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT") or os.environ.get("FRIHET_PORT") or "8080")
ADMIN_PW = os.environ.get("FRIHET_ADMIN_PASSWORD", "")
# 환경변수가 없을 때 쓰는 기본 비밀번호 (원문이 아닌 SHA-256 값으로 보관)
PW_SALT = "frihet-layout-v1:"
DEFAULT_PW_HASH = "420e42134219b0e18fa215397464ac0fb616f241c41e60d2c2aa6f67dac6a249"

BASE = Path(__file__).resolve().parent
INDEX = BASE / "index.html"
SEED = BASE / "layout.json"
DATA_DIR = Path(os.environ.get("FRIHET_DATA_DIR") or (BASE / "data"))
LAYOUT = DATA_DIR / "layout.json"
BACKUPS = DATA_DIR / "backups"
MAX_BODY = 1_000_000
KEEP_BACKUPS = 200


def read_layout():
    try:
        return json.loads(LAYOUT.read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass
    try:  # 처음 실행: 저장소에 있는 layout.json 을 시작 내용으로 사용
        seed = json.loads(SEED.read_text(encoding="utf-8"))
        return {"version": 0, "updatedAt": None, "slots": seed.get("slots")}
    except Exception:
        return {"version": 0, "updatedAt": None, "slots": None}


def write_layout(slots):
    DATA_DIR.mkdir(exist_ok=True)
    BACKUPS.mkdir(exist_ok=True)
    current = read_layout()
    if LAYOUT.exists():  # 이전 버전 백업
        stamp = time.strftime("%Y%m%d-%H%M%S")
        (BACKUPS / f"layout-{stamp}-v{current['version']}.json").write_text(
            LAYOUT.read_text(encoding="utf-8"), encoding="utf-8")
        old = sorted(BACKUPS.glob("layout-*.json"))
        for f in old[:-KEEP_BACKUPS]:
            f.unlink(missing_ok=True)
    new = {"version": current["version"] + 1, "updatedAt": int(time.time()), "slots": slots}
    tmp = LAYOUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(new, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, LAYOUT)  # 쓰는 도중 끊겨도 파일이 깨지지 않도록 원자적 교체
    return new


class Handler(BaseHTTPRequestHandler):
    server_version = "FrihetLayout/1.0"

    # tailscale serve 로 /layout 같은 하위 경로에 붙여도 동작하도록 끝부분으로 판별
    def route(self):
        path = self.path.split("?", 1)[0]
        if path.endswith("/api/layout"):
            return "layout"
        if path.endswith("/api/login"):
            return "login"
        if "." in path.rsplit("/", 1)[-1] and not path.endswith("index.html"):
            return None  # favicon.ico 등 다른 파일 요청
        return "index"   # /, /layout, /layout/, /index.html 모두 배치도 화면

    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def is_admin(self):
        given = self.headers.get("X-Admin-Password", "")
        if ADMIN_PW:
            return hmac.compare_digest(given.encode(), ADMIN_PW.encode())
        h = hashlib.sha256((PW_SALT + given).encode()).hexdigest()
        return hmac.compare_digest(h, DEFAULT_PW_HASH)

    def do_GET(self):
        r = self.route()
        if r == "index":
            body = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif r == "layout":
            self.send_json(200, read_layout())
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.route() != "login":
            return self.send_json(404, {"error": "not found"})
        if not self.is_admin():
            time.sleep(1)  # 무작위 대입 속도 늦추기
            return self.send_json(401, {"error": "unauthorized"})
        self.send_json(200, {"ok": True})

    def do_PUT(self):
        if self.route() != "layout":
            return self.send_json(404, {"error": "not found"})
        if not self.is_admin():
            time.sleep(1)
            return self.send_json(401, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self.send_json(400, {"error": "bad size"})
        try:
            payload = json.loads(self.rfile.read(length))
            slots = payload["slots"]
            assert isinstance(slots, dict)
        except Exception:
            return self.send_json(400, {"error": "bad json"})
        saved = write_layout(slots)
        self.send_json(200, {"version": saved["version"], "updatedAt": saved["updatedAt"]})

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), fmt % args))


if __name__ == "__main__":
    if not ADMIN_PW:
        print("FRIHET_ADMIN_PASSWORD 가 없어 기본 관리자 비밀번호를 사용합니다.")
    if not INDEX.exists():
        sys.exit(f"{INDEX} 파일이 없습니다. server.py 와 같은 폴더에 index.html 을 두세요.")
    print(f"프리헷 배치도 서버 실행 중: http://{HOST}:{PORT}/")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
