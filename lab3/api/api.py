"""
Serwer zasobów (Resource Server) dla laboratorium 3.

Przyjmuje wyłącznie żądania z tokenem dostępowym typu Bearer (RFC 6750).
Token jest sprawdzany na dwa sposoby:
  1. lokalnie - podpis RS256 (klucze z JWKS serwera autoryzacyjnego), iss, aud, exp,
  2. przez introspekcję (RFC 7662) - czy token nie został unieważniony (np. po wylogowaniu).
Dostęp do zasobów jest przydzielany według prostego modelu RBAC (rola -> uprawnienia).
"""
import logging
import os
import time

import jwt
import requests
from flask import Flask, g, jsonify, request

ISSUER = os.environ["OIDC_ISSUER"]                      # http://localhost:8080/realms/pbksi
INTERNAL = os.environ["OIDC_INTERNAL_URL"]              # http://keycloak:8080/realms/pbksi
AUDIENCE = os.environ.get("API_AUDIENCE", "pbksi-api")
API_CLIENT_ID = os.environ.get("API_CLIENT_ID", "pbksi-api")
API_CLIENT_SECRET = os.environ["API_CLIENT_SECRET"]

JWKS = jwt.PyJWKClient(f"{INTERNAL}/protocol/openid-connect/certs", cache_keys=True, lifespan=300)
INTROSPECT_URL = f"{INTERNAL}/protocol/openid-connect/token/introspect"

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s api %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("api")

# ---------------------------------------------------------------- RBAC ---
# Model RBAC: użytkownik -> role (z tokenu, nadawane w Keycloaku) -> uprawnienia -> zasoby.
ROLE_PERMISSIONS = {
    "admin": {"profile:read", "grades:read", "users:read", "audit:read"},
    "user": {"profile:read", "grades:read"},
    "guest": {"profile:read"},  # zalogowany, ale bez żadnej roli aplikacyjnej
}

# Dane "chronionych zasobów"
GRADES = {
    "anna": [
        {"przedmiot": "Problemy bezpieczeństwa komputerowego w SI", "ocena": 5.0},
        {"przedmiot": "Systemy rozproszone", "ocena": 4.5},
        {"przedmiot": "Seminarium magisterskie", "ocena": 5.0},
    ],
    "jan": [
        {"przedmiot": "Problemy bezpieczeństwa komputerowego w SI", "ocena": 4.0},
        {"przedmiot": "Systemy rozproszone", "ocena": 3.5},
        {"przedmiot": "Uczenie maszynowe", "ocena": 4.5},
    ],
}
USERS = [
    {"login": "anna", "imie_nazwisko": "Anna Kowalska", "role": ["admin", "user"]},
    {"login": "jan", "imie_nazwisko": "Jan Nowak", "role": ["user"]},
    {"login": "ewa", "imie_nazwisko": "Ewa Wiśniewska", "role": []},
]


def roles_of(claims):
    roles = set(claims.get("realm_access", {}).get("roles", [])) & set(ROLE_PERMISSIONS)
    return sorted(roles) or ["guest"]


def permissions_of(roles):
    perms = set()
    for r in roles:
        perms |= ROLE_PERMISSIONS.get(r, set())
    return perms


def bearer_error(status, error=None, description=None, scope=None):
    """Odpowiedź błędu zgodna z RFC 6750, rozdz. 3 (nagłówek WWW-Authenticate)."""
    parts = ['Bearer realm="pbksi-api"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        parts.append(f'error_description="{description}"')
    if scope:
        parts.append(f'scope="{scope}"')
    resp = jsonify({"error": error or "unauthorized", "error_description": description})
    resp.status_code = status
    resp.headers["WWW-Authenticate"] = ", ".join(parts)
    return resp


def authenticate():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # RFC 6750: brak tokenu -> 401 bez kodu błędu
        return bearer_error(401)
    token = auth[len("Bearer "):].strip()
    try:
        key = JWKS.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER,
                            options={"require": ["exp", "iat", "sub"]})
    except jwt.ExpiredSignatureError:
        log.info("401 invalid_token (expired)")
        return bearer_error(401, "invalid_token", "The access token expired")
    except jwt.InvalidAudienceError:
        return bearer_error(401, "invalid_token", "Wrong audience")
    except jwt.PyJWTError as e:
        log.info("401 invalid_token (%s)", e)
        return bearer_error(401, "invalid_token", "The access token is invalid")

    # Introspekcja - wykrywa tokeny unieważnione przed upływem exp (np. po wylogowaniu)
    r = requests.post(INTROSPECT_URL, data={"token": token, "token_type_hint": "access_token"},
                      auth=(API_CLIENT_ID, API_CLIENT_SECRET), timeout=5)
    if r.status_code != 200 or not r.json().get("active"):
        log.info("401 invalid_token (revoked) sub=%s", claims.get("preferred_username"))
        return bearer_error(401, "invalid_token", "The access token has been revoked")

    g.claims = claims
    g.user = claims.get("preferred_username")
    g.roles = roles_of(claims)
    g.perms = permissions_of(g.roles)
    return None


def require(permission):
    def deco(fn):
        def wrapper(*a, **kw):
            err = authenticate()
            if err is not None:
                return err
            if permission not in g.perms:
                log.info("403 insufficient_scope user=%s roles=%s need=%s", g.user, g.roles, permission)
                return bearer_error(403, "insufficient_scope",
                                    f"Permission {permission} required", scope=permission)
            log.info("200 user=%s roles=%s %s %s", g.user, g.roles, request.method, request.path)
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco


@app.get("/api/me")
@require("profile:read")
def me():
    c = g.claims
    return jsonify({
        "sub": c["sub"],
        "login": c.get("preferred_username"),
        "imie_nazwisko": c.get("name"),
        "email": c.get("email"),
        "role": g.roles,
        "uprawnienia": sorted(g.perms),
        "scope": c.get("scope"),
        "token_wygasa_za_s": int(c["exp"] - time.time()),
    })


@app.get("/api/grades")
@require("grades:read")
def grades():
    return jsonify({"login": g.user, "oceny": GRADES.get(g.user, [])})


@app.get("/api/admin/users")
@require("users:read")
def admin_users():
    out = []
    for u in USERS:
        oceny = [x["ocena"] for x in GRADES.get(u["login"], [])]
        out.append({**u, "srednia": round(sum(oceny) / len(oceny), 2) if oceny else None})
    return jsonify({"uzytkownicy": out})


@app.get("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
