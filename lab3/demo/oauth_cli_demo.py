#!/usr/bin/env python3
"""
Authorization Code Flow (kroki A-E) krok po kroku, "ręcznie", bez przeglądarki.

Skrypt sam gra rolę przeglądarki (User-Agent) i klienta, żeby pokazać surowe żądania HTTP:
  A  GET  /auth?response_type=code&client_id=...&state=...&code_challenge=...
  B  POST formularz logowania + zgoda (consent) właściciela zasobu
  C  302 Location: http://localhost:5000/callback?code=...&state=...
  D  POST /token  grant_type=authorization_code (+ uwierzytelnienie klienta)
  E  200 {access_token, refresh_token, expires_in, ...}
Następnie: żądanie zasobu z Bearer, odświeżenie tokenu, próba ponownego użycia starego
refresh tokenu (rotacja), unieważnienie (RFC 7009) i introspekcja (RFC 7662).

Użycie: python3 oauth_cli_demo.py [login] [hasło]   (domyślnie jan / jan123 - konto testowe z realmu)
"""
import base64
import hashlib
import html
import json
import re
import secrets
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import jwt
import requests

KC = "http://localhost:8080/realms/pbksi/protocol/openid-connect"
API = "http://localhost:5001"
CLIENT_ID, CLIENT_SECRET = "pbksi-webapp", "lab3-client-secret-zmien-mnie"
API_ID, API_SECRET = "pbksi-api", "lab3-api-secret-zmien-mnie"
REDIRECT = "http://localhost:5000/callback"
USER, PASSWORD = (sys.argv[1:3] + ["jan", "jan123"][len(sys.argv[1:3]):])


def hdr(t):
    print(f"\n{'=' * 78}\n{t}\n{'=' * 78}")


def short(tok):
    return f"{tok[:20]}...{tok[-8:]}" if isinstance(tok, str) and len(tok) > 40 else tok


TOKEN_KEYS = ("access_token", "refresh_token", "id_token", "code")


def show(resp, full=False):
    print(f"HTTP {resp.status_code} {resp.reason}")
    for h in ("Location", "WWW-Authenticate", "Cache-Control", "Pragma", "Content-Type"):
        if h in resp.headers:
            v = resp.headers[h]
            print(f"{h}: {v if len(v) < 160 else v[:160] + '...'}")
    if resp.headers.get("Content-Type", "").startswith("application/json"):
        j = resp.json()
        if not full and isinstance(j, dict):
            j = {k: (short(v) if k in TOKEN_KEYS else v) for k, v in j.items()}
        print(json.dumps(j, indent=2, ensure_ascii=False))


def form_of(page, base):
    """Wyciąga action i ukryte pola pierwszego formularza na stronie Keycloaka."""
    action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page).group(1))
    fields = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
    return urljoin(base, action), fields


def times(claims):
    f = lambda t: datetime.fromtimestamp(t).strftime("%H:%M:%S")
    return f"iat={f(claims['iat'])} exp={f(claims['exp'])} -> czas życia {claims['exp'] - claims['iat']} s"


class Browser:
    """Minimalna "przeglądarka": pamięta ciasteczka Keycloaka między żądaniami.

    Keycloak ustawia ciasteczka z flagą Secure także na http://localhost (przeglądarki traktują
    localhost jako bezpieczny kontekst), a http.cookiejar w Pythonie ich nie odsyła - dlatego
    ciasteczka są tu przechowywane ręcznie."""
    def __init__(self):
        self.jar = {}

    def _go(self, method, url, **kw):
        r = requests.request(method, url, cookies=self.jar, **kw)
        for resp in r.history + [r]:
            self.jar.update({c.name: c.value for c in resp.cookies})
        return r

    def get(self, url, **kw):
        return self._go("GET", url, **kw)

    def post(self, url, **kw):
        return self._go("POST", url, **kw)


ua = Browser()


def authorize(verbose=True):
    """Kroki A-E. Zwraca (odpowiedź tokenową, parametry żądania A, dane żądania D)."""
    out = print if verbose else (lambda *a, **k: None)
    state = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
              "scope": "openid profile email roles", "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if verbose:
        hdr("A. Żądanie autoryzacyjne (przeglądarka -> serwer autoryzacyjny)")
    out(f"GET {KC}/auth?{urlencode(params)}")
    r = ua.get(f"{KC}/auth", params=params, allow_redirects=False)
    if r.status_code == 200:
        out(f"HTTP {r.status_code} -> strona logowania Keycloaka ({len(r.text)} B HTML)")
        if verbose:
            hdr(f"B. Uwierzytelnienie właściciela zasobu ({USER}) i zgoda na zakres")
        action, fields = form_of(r.text, r.url)
        out(f"POST {action.split('?')[0]}?...  username={USER}&password=***")
        r = ua.post(action, data={**fields, "username": USER, "password": PASSWORD, "credentialId": ""},
                    allow_redirects=False)
    if r.status_code == 302 and r.headers["Location"].startswith("http://localhost:8080"):
        out(f"HTTP 302 -> {r.headers['Location'].split('?')[0]} (wymagana akcja OAUTH_GRANT = zgoda)")
        r = ua.get(r.headers["Location"], allow_redirects=False)
    if r.status_code == 200 and "accept" in r.text.lower():
        action, fields = form_of(r.text, r.url)
        scopes = re.findall(r'<li[^>]*>\s*<span>([^<]+)</span>', r.text)
        out(f"HTTP 200 -> ekran zgody, aplikacja prosi o: {', '.join(x.strip() for x in scopes)}")
        out(f"POST {action.split('?')[0]}?...  accept=Yes")
        r = ua.post(action, data={**fields, "accept": "Yes"}, allow_redirects=False)

    if verbose:
        hdr("C. Przekierowanie z kodem autoryzacyjnym (serwer autoryzacyjny -> przeglądarka -> klient)")
        show(r)
    q = parse_qs(urlparse(r.headers["Location"]).query)
    code = q["code"][0]
    out(f"\nstate zgodny z wysłanym: {q['state'][0] == state}")
    out(f"code = {short(code)}")

    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT, "code_verifier": verifier}
    if verbose:
        hdr("D. Wymiana kodu na token (klient -> punkt tokenów, back-channel)")
        print(f"POST {KC}/token\nAuthorization: Basic base64({CLIENT_ID}:***)\n"
              f"Content-Type: application/x-www-form-urlencoded\n\n"
              f"grant_type=authorization_code&code={short(code)}&redirect_uri={REDIRECT}"
              f"&code_verifier={verifier[:12]}...")
        hdr("E. Odpowiedź serwera autoryzacyjnego z tokenami")
    r = requests.post(f"{KC}/token", data=data, auth=(CLIENT_ID, CLIENT_SECRET))
    if verbose:
        show(r)
    return r.json(), params, data


def api(path, token, label=None):
    print(f"\nGET {API}{path}\nAuthorization: Bearer {short(token) if token else '-'}" + (f"   ({label})" if label else ""))
    show(requests.get(f"{API}{path}", headers={"Authorization": f"Bearer {token}"} if token else {}), full=True)


def introspect(token):
    r = requests.post(f"{KC}/token/introspect", data={"token": token}, auth=(API_ID, API_SECRET))
    return r.json().get("active")


def refresh(rt):
    return requests.post(f"{KC}/token", data={"grant_type": "refresh_token", "refresh_token": rt},
                         auth=(CLIENT_ID, CLIENT_SECRET))


# ===================================================================== 1 ===
tok, params, data = authorize()
at, rt = tok["access_token"], tok["refresh_token"]
atc, rtc = (jwt.decode(t, options={"verify_signature": False}) for t in (at, rt))
print(f"\naccess_token : {times(atc)}")
print(f"refresh_token: {times(rtc)}  (= {(rtc['exp'] - rtc['iat']) / 3600:g} h)")
print(f"access_token: realm_access.roles = {atc.get('realm_access', {}).get('roles')}, aud = {atc.get('aud')}")

hdr("Ponowne użycie tego samego kodu autoryzacyjnego (kod jest jednorazowy)")
show(requests.post(f"{KC}/token", data=data, auth=(CLIENT_ID, CLIENT_SECRET)))

hdr("PKCE: przechwycony kod bez właściwego code_verifier jest bezużyteczny")
r = ua.get(f"{KC}/auth", params={**params, "state": "drugi"}, allow_redirects=False)
code2 = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
print(f"nowy kod (sesja SSO już istnieje, logowanie nie jest potrzebne): {short(code2)}")
print("POST /token ... code=<nowy kod>&code_verifier=<inny, losowy>")
show(requests.post(f"{KC}/token", data={**data, "code": code2, "code_verifier": secrets.token_urlsafe(64)},
                   auth=(CLIENT_ID, CLIENT_SECRET)))
r = ua.get(f"{KC}/auth", params={**params, "state": "trzeci"}, allow_redirects=False)
code3 = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
print("\nPOST /token ... poprawny code i code_verifier, ale zły client_secret")
show(requests.post(f"{KC}/token", data={**data, "code": code3}, auth=(CLIENT_ID, "zly-sekret")))

# ===================================================================== 2 ===
hdr(f"Żądania zasobów z tokenem Bearer (użytkownik {USER})")
for path in ("/api/me", "/api/grades", "/api/admin/users"):
    api(path, at)

hdr("Żądanie bez tokenu i z podrobionym tokenem")
api("/api/me", None, "bez nagłówka Authorization")
api("/api/me", at[:-10] + "A" * 10, "token ze zmienionym podpisem")

# ===================================================================== 3 ===
hdr("Odświeżenie access tokenu (grant_type=refresh_token)")
time.sleep(2)
print(f"POST {KC}/token\nAuthorization: Basic base64({CLIENT_ID}:***)\n\n"
      f"grant_type=refresh_token&refresh_token={short(rt)}")
r = refresh(rt)
show(r)
new = r.json()
nrc = jwt.decode(new["refresh_token"], options={"verify_signature": False})
print(f"\nnowy refresh_token różny od starego: {new['refresh_token'] != rt}")
print(f"nowy refresh_token: {times(nrc)}")
print("  -> exp się nie przesuwa: refresh token żyje maks. 6 h od zalogowania (ssoSessionMaxLifespan)")
print(f"introspekcja nowego access tokenu: active = {introspect(new['access_token'])}")

hdr("Ponowne użycie STAREGO refresh tokenu (rotacja: revokeRefreshToken=true, refreshTokenMaxReuse=0)")
show(refresh(rt))
print(f"\nintrospekcja NOWEGO access tokenu po tej próbie: active = {introspect(new['access_token'])}")
print("  -> wykrycie ponownego użycia unieważnia całą sesję (całą \"rodzinę\" tokenów),")
print("     więc złodziej starego refresh tokenu nie zyskuje nic, a prawowity klient musi się zalogować ponownie")
api("/api/me", new["access_token"], "nowy access token po wykryciu ponownego użycia")

# ===================================================================== 4 ===
hdr("Nowe logowanie (bez wypisywania kroków) i unieważnienie tokenów jak przy wylogowaniu")
tok, _, _ = authorize(verbose=False)
at2, rt2 = tok["access_token"], tok["refresh_token"]
print(f"nowe tokeny: access {short(at2)}, refresh {short(rt2)}")
print(f"introspekcja access tokenu: active = {introspect(at2)}")
for t, hint in ((rt2, "refresh_token"), (at2, "access_token")):
    r = requests.post(f"{KC}/revoke", data={"token": t, "token_type_hint": hint}, auth=(CLIENT_ID, CLIENT_SECRET))
    print(f"POST {KC}/revoke  token_type_hint={hint} -> HTTP {r.status_code}")
print(f"introspekcja access tokenu po revoke: active = {introspect(at2)}")
api("/api/me", at2, "unieważniony access token")
print("\nPOST /token grant_type=refresh_token (unieważniony refresh token)")
show(refresh(rt2))
