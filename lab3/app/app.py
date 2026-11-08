"""
Klient OAuth 2.0 (aplikacja webowa) - laboratorium 3 PBKSI.

Przepływ: Authorization Code Flow (RFC 6749, rozdz. 4.1) z PKCE (RFC 7636) i OpenID Connect.
Serwer autoryzacyjny: Keycloak (realm "pbksi"), serwer zasobów: usługa "api".

Kroki A-E z instrukcji są zaznaczone w komentarzach.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime
from functools import wraps
from urllib.parse import urlencode

import jwt
import requests
from flask import (Flask, abort, g, make_response, redirect, render_template, request,
                   url_for)

from store import SessionStore

# --------------------------------------------------------------- konfiguracja ---
PUBLIC = os.environ["OIDC_PUBLIC_URL"]       # adres Keycloaka widziany przez przeglądarkę
INTERNAL = os.environ["OIDC_INTERNAL_URL"]   # adres Keycloaka widziany z kontenera (back-channel)
ISSUER = PUBLIC
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
APP_URL = os.environ.get("APP_URL", "http://localhost:5000")
REDIRECT_URI = f"{APP_URL}/callback"
API_URL = os.environ["API_URL"]
SCOPE = "openid profile email roles"
LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
COOKIE = "pbksi_sid"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
REFRESH_MARGIN = 10  # s - odśwież access token, gdy do końca ważności zostało mniej niż tyle

EP = {
    "authorize": f"{PUBLIC}/protocol/openid-connect/auth",
    "token": f"{INTERNAL}/protocol/openid-connect/token",
    "revoke": f"{INTERNAL}/protocol/openid-connect/revoke",
    "logout": f"{INTERNAL}/protocol/openid-connect/logout",
    "jwks": f"{INTERNAL}/protocol/openid-connect/certs",
}
JWKS = jwt.PyJWKClient(EP["jwks"], cache_keys=True, lifespan=300)

os.makedirs(LOG_DIR, exist_ok=True)
AUDIT_LOG = os.path.join(LOG_DIR, "audit.log")
TRACE_LOG = os.path.join(LOG_DIR, "oauth_trace.log")

DB_PATH = os.environ.get("DB_PATH", "/app/data/sessions.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
store = SessionStore(DB_PATH, os.environ["TOKEN_ENC_KEY"].encode(), ttl=6 * 3600)

app = Flask(__name__)


# ----------------------------------------------------------------- audyt ---
def audit(event, **kv):
    """Audyt bezpieczeństwa: jedna linia na zdarzenie, format jak w instrukcji."""
    extra = " ".join(f"{k}={v}" for k, v in kv.items() if v is not None)
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {event}" + (f" [{extra}]" if extra else "")
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print("AUDIT " + line, flush=True)


def short(tok):
    return f"{tok[:16]}...{tok[-6:]} ({len(tok)} B)" if isinstance(tok, str) and len(tok) > 30 else tok


def trace(title, req_line, req_body, resp):
    """Zapis komunikacji back-channel (bez sekretów, tokeny skrócone) - do sprawozdania."""
    body = {k: ("***" if k in ("client_secret",) else short(v)) for k, v in req_body.items()}
    try:
        rj = resp.json()
        rj = {k: short(v) for k, v in rj.items()} if isinstance(rj, dict) else rj
        rtxt = json.dumps(rj, indent=2, ensure_ascii=False)
    except ValueError:
        rtxt = resp.text[:300]
    with open(TRACE_LOG, "a", encoding="utf-8") as f:
        f.write(f"===== {datetime.now():%Y-%m-%d %H:%M:%S} {title}\n"
                f"{req_line}\nAuthorization: Basic base64({CLIENT_ID}:***)\n"
                f"Content-Type: application/x-www-form-urlencoded\n\n{urlencode(body)}\n\n"
                f"HTTP {resp.status_code}\n{rtxt}\n\n")


def token_request(title, data):
    r = requests.post(EP["token"], data=data, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
    trace(title, "POST /realms/pbksi/protocol/openid-connect/token HTTP/1.1", data, r)
    return r


# ---------------------------------------------------------------- sesje ---
def load_session():
    sid = request.cookies.get(COOKIE)
    return sid, store.load(sid)


def set_cookie(resp, sid):
    resp.set_cookie(COOKIE, sid, httponly=True, samesite="Lax", secure=COOKIE_SECURE, path="/",
                    max_age=6 * 3600)
    return resp


def destroy_session(sid):
    if sid:
        store.delete(sid)


@app.before_request
def attach_session():
    g.sid, g.sess = load_session()
    g.logged = bool(g.sess and g.sess.get("user"))


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                               "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"  # "no-referrer" powoduje Origin: null w POST
    resp.headers["Cache-Control"] = "no-store"
    return resp


def csrf_protect(fn):
    """Ochrona formularzy (POST) przed CSRF: token synchronizujący + sprawdzenie nagłówka Origin."""
    @wraps(fn)
    def wrapper(*a, **kw):
        sent = request.form.get("csrf_token", "")
        good = g.sess.get("csrf", "") if g.sess else ""
        origin = request.headers.get("Origin")
        if not good or not secrets.compare_digest(sent, good) or (origin and origin != APP_URL):
            audit("CSRF Attempt Blocked", path=request.path, origin=origin, ip=request.remote_addr,
                  user=(g.sess or {}).get("user", {}).get("login"))
            abort(403, "Nieprawidłowy token CSRF")
        return fn(*a, **kw)
    return wrapper


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not g.logged:
            return redirect(url_for("index"))
        return fn(*a, **kw)
    return wrapper


# ----------------------------------------------------------- tokeny ---
def store_tokens(sess, tj):
    now = int(time.time())
    sess["tokens"] = {
        "access_token": tj["access_token"],
        "refresh_token": tj.get("refresh_token", sess.get("tokens", {}).get("refresh_token")),
        "id_token": tj.get("id_token", sess.get("tokens", {}).get("id_token")),
        "expires_at": now + int(tj["expires_in"]),
        "refresh_expires_at": now + int(tj.get("refresh_expires_in", 0)),
        "issued_at": now,
    }


def refresh_tokens(reason="auto"):
    """Odświeżenie access tokenu za pomocą refresh tokenu (RFC 6749, rozdz. 6)."""
    sess, user = g.sess, g.sess["user"]["login"]
    t = sess["tokens"]
    if t["refresh_expires_at"] <= time.time():
        audit("Token Expired", user=user, token="refresh_token", detail="re-login required")
        destroy_session(g.sid)
        return False
    r = token_request(f"Refresh token grant ({reason})",
                      {"grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
    if r.status_code != 200:
        err = r.json().get("error_description", r.text) if r.headers.get("content-type", "").startswith(
            "application/json") else r.text
        audit("Token Expired", user=user, token="refresh_token", detail=f"refresh failed: {err}")
        destroy_session(g.sid)
        return False
    store_tokens(sess, r.json())
    store.save(g.sid, sess)
    audit("Access Token Refreshed", user=user, reason=reason,
          access_valid_s=sess["tokens"]["expires_at"] - int(time.time()))
    return True


def access_token():
    t = g.sess["tokens"]
    now = time.time()
    if t["expires_at"] - REFRESH_MARGIN <= now:
        audit("Access Token Expired" if t["expires_at"] <= now else "Access Token Expiring",
              user=g.sess["user"]["login"], exp=datetime.fromtimestamp(t["expires_at"]).strftime("%H:%M:%S"))
        if not refresh_tokens("access token expired"):
            return None
    return g.sess["tokens"]["access_token"]


def call_api(path):
    """Żądanie do serwera zasobów z tokenem Bearer w nagłówku Authorization (RFC 6750, 2.1)."""
    tok = access_token()
    if tok is None:
        return None
    r = requests.get(f"{API_URL}{path}", headers={"Authorization": f"Bearer {tok}"}, timeout=10)
    if r.status_code == 401:
        audit("Token Rejected", user=g.sess["user"]["login"], resource=path,
              detail=r.headers.get("WWW-Authenticate"))
    return r


def decode_unverified(tok):
    try:
        return jwt.decode(tok, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


# ------------------------------------------------------------- widoki ---
RESOURCES = {
    "profil": ("/api/me", "Mój profil", "profile:read"),
    "oceny": ("/api/grades", "Moje oceny", "grades:read"),
    "uzytkownicy": ("/api/admin/users", "Użytkownicy systemu", "users:read"),
}


def current_perms():
    r = call_api("/api/me")
    if r is None or r.status_code != 200:
        return None, None
    me = r.json()
    return me, set(me["uprawnienia"])


@app.get("/")
def index():
    if not g.logged:
        return render_template("index.html", logged=False, msg=request.args.get("msg"))
    me, perms = current_perms()
    if me is None:
        return session_lost()
    return render_template("index.html", logged=True, me=me, perms=perms, resources=RESOURCES,
                           csrf=g.sess["csrf"])


def session_lost():
    resp = redirect(url_for("index", msg="Sesja wygasła - zaloguj się ponownie."))
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/login")
def login():
    # Krok A: przekierowanie przeglądarki do punktu autoryzacji z client_id, scope, state, redirect_uri
    state = secrets.token_urlsafe(24)       # ochrona przed CSRF na /callback
    nonce = secrets.token_urlsafe(24)       # wiązanie ID tokenu z tym żądaniem (replay)
    verifier = secrets.token_urlsafe(64)    # PKCE
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    destroy_session(g.sid)
    sid = store.create({"pending": {"state": state, "nonce": nonce, "verifier": verifier,
                                    "created": int(time.time())}})
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    with open(TRACE_LOG, "a", encoding="utf-8") as f:
        f.write(f"===== {datetime.now():%Y-%m-%d %H:%M:%S} Krok A - authorization request (front-channel)\n"
                f"HTTP 302 Location: {EP['authorize']}?{urlencode(params)}\n\n")
    audit("Authorization Request", ip=request.remote_addr, scope=SCOPE.replace(" ", ","))
    return set_cookie(redirect(f"{EP['authorize']}?{urlencode(params)}"), sid)


@app.get("/callback")
def callback():
    # Krok C: serwer autoryzacyjny odsyła przeglądarkę z kodem i stanem
    pending = (g.sess or {}).get("pending")
    if "error" in request.args:
        audit("Login Failed", reason=request.args["error"], detail=request.args.get("error_description"),
              ip=request.remote_addr)
        destroy_session(g.sid)
        return render_template("error.html", title="Logowanie nieudane",
                               text=f"Serwer autoryzacyjny zwrócił błąd: {request.args['error']} "
                                    f"({request.args.get('error_description', '')})"), 400
    state = request.args.get("state", "")
    if not pending or not secrets.compare_digest(state, pending["state"]):
        audit("Login Failed", reason="state mismatch (possible CSRF)", ip=request.remote_addr)
        return render_template("error.html", title="Logowanie odrzucone",
                               text="Parametr state nie zgadza się z wartością zapisaną w sesji. "
                                    "Żądanie mogło zostać spreparowane (atak CSRF)."), 400
    if time.time() - pending["created"] > 600:
        audit("Login Failed", reason="authorization request too old", ip=request.remote_addr)
        return render_template("error.html", title="Logowanie nieudane", text="Żądanie wygasło."), 400

    # Krok D: wymiana kodu na token (back-channel, klient uwierzytelnia się client_secret)
    r = token_request("Krok D/E - authorization_code grant", {
        "grant_type": "authorization_code",
        "code": request.args.get("code", ""),
        "redirect_uri": REDIRECT_URI,
        "code_verifier": pending["verifier"],
    })
    if r.status_code != 200:
        audit("Login Failed", reason="token endpoint error", detail=r.json().get("error"), ip=request.remote_addr)
        destroy_session(g.sid)
        return render_template("error.html", title="Logowanie nieudane",
                               text=f"Wymiana kodu na token nie powiodła się: {r.text}"), 400
    tj = r.json()

    # Krok E (weryfikacja po stronie klienta): podpis i zawartość ID tokenu
    try:
        key = JWKS.get_signing_key_from_jwt(tj["id_token"])
        idt = jwt.decode(tj["id_token"], key.key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER)
        if not secrets.compare_digest(idt.get("nonce", ""), pending["nonce"]):
            raise jwt.InvalidTokenError("nonce mismatch")
    except (jwt.PyJWTError, KeyError) as e:
        audit("Login Failed", reason=f"invalid id_token: {e}", ip=request.remote_addr)
        destroy_session(g.sid)
        return render_template("error.html", title="Logowanie nieudane", text="Niepoprawny ID token."), 400

    # nowa sesja po zalogowaniu (ochrona przed session fixation)
    destroy_session(g.sid)
    sess = {"user": {"login": idt.get("preferred_username"), "name": idt.get("name"), "sub": idt["sub"]},
            "csrf": secrets.token_urlsafe(32), "login_at": int(time.time())}
    store_tokens(sess, tj)
    sid = store.create(sess)
    audit("Login Success", user=sess["user"]["login"], ip=request.remote_addr,
          access_valid_s=tj["expires_in"], refresh_valid_s=tj.get("refresh_expires_in"))
    return set_cookie(redirect(url_for("index")), sid)


@app.get("/zasob/<name>")
@login_required
def resource(name):
    if name not in RESOURCES:
        abort(404)
    path, title, perm = RESOURCES[name]
    r = call_api(path)
    if r is None:
        return session_lost()
    if r.status_code == 403:
        audit("Access Denied", user=g.sess["user"]["login"], resource=path, need=perm)
        return render_template("error.html", title="Brak dostępu (403)",
                               text=f"Twoja rola nie daje uprawnienia {perm}. "
                                    f"Odpowiedź API: WWW-Authenticate: {r.headers.get('WWW-Authenticate')}"), 403
    if r.status_code == 401:
        return session_lost()
    data = r.json()
    audit("Resource Access", user=g.sess["user"]["login"], resource=path)
    return render_template("resource.html", name=name, title=title, data=data, path=path,
                           raw=json.dumps(data, indent=2, ensure_ascii=False))


@app.get("/tokeny")
@login_required
def tokens():
    t = g.sess["tokens"]
    now = int(time.time())
    at, rt, it = (decode_unverified(t[k]) for k in ("access_token", "refresh_token", "id_token"))
    info = {
        "access": {"claims": at, "raw": short(t["access_token"]), "left": t["expires_at"] - now,
                   "life": at.get("exp", 0) - at.get("iat", 0)},
        "refresh": {"claims": rt, "raw": short(t["refresh_token"]), "left": t["refresh_expires_at"] - now,
                    "life": rt.get("exp", 0) - rt.get("iat", 0)},
        "id": {"claims": it, "raw": short(t["id_token"])},
    }
    fmt = lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "-"
    return render_template("tokens.html", info=info, fmt=fmt, csrf=g.sess["csrf"],
                           json=lambda d: json.dumps(d, indent=2, ensure_ascii=False))


@app.post("/odswiez")
@csrf_protect
@login_required
def refresh_now():
    if not refresh_tokens("manual"):
        return session_lost()
    return redirect(url_for("tokens"))


@app.get("/audyt")
@login_required
def audit_view():
    me, perms = current_perms()
    if me is None:
        return session_lost()
    if "audit:read" not in perms:
        audit("Access Denied", user=g.sess["user"]["login"], resource="/audyt", need="audit:read")
        return render_template("error.html", title="Brak dostępu (403)",
                               text="Dziennik audytu jest dostępny tylko dla roli admin."), 403
    with open(AUDIT_LOG, encoding="utf-8") as f:
        lines = f.readlines()[-200:]
    return render_template("audit.html", lines=reversed(lines))


@app.post("/wyloguj")
@csrf_protect
@login_required
def logout():
    t, user = g.sess["tokens"], g.sess["user"]["login"]
    # 1. jawne unieważnienie access tokenu (RFC 7009) - od tej chwili introspekcja zwraca active=false
    r1 = requests.post(EP["revoke"], data={"token": t["access_token"], "token_type_hint": "access_token"},
                       auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
    # 2. zakończenie sesji na serwerze autoryzacyjnym - unieważnia refresh token i sesję SSO
    r2 = requests.post(EP["logout"], data={"refresh_token": t["refresh_token"]},
                       auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
    # 3. usunięcie tokenów z magazynu aplikacji i ciasteczka z przeglądarki
    destroy_session(g.sid)
    audit("Logout", user=user, revoke_access_token=r1.status_code, idp_session_logout=r2.status_code,
          local_tokens="deleted")
    resp = redirect(url_for("index", msg="Wylogowano. Tokeny zostały unieważnione i usunięte."))
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", title="403 Forbidden", text=e.description), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
