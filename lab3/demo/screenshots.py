#!/usr/bin/env python3
"""
Przejście przez aplikację w przeglądarce (Chromium, Playwright) i zrzuty ekranu do README.

Konta testowe pochodzą z keycloak/realm-pbksi.json:
  anna / anna123  - role admin, user
  jan  / jan123   - rola user
  ewa  / ewa123   - brak ról aplikacyjnych (guest)
"""
import subprocess
import sys
import time
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

APP = "http://localhost:5000"
KC = "http://localhost:8080"
OUT = Path(__file__).resolve().parent.parent / "img"
OUT.mkdir(exist_ok=True)
WAIT_EXPIRY = "--no-wait" not in sys.argv
DUMP_DB = """
import sqlite3
for h, d, c, e in sqlite3.connect("/app/data/sessions.db").execute("select * from sessions"):
    print(f"sid_hash = {h}\\ncreated  = {c}   expires = {e}\\ndata     = {d[:100].decode()}... ({len(d)} B)\\n")
"""


def shot(page, name, full=True):
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=full)
    print("zrzut:", name)


def kc_login(page, user, password, consent="accept", name_prefix=None):
    page.goto(APP)
    page.click("text=Zaloguj przez Keycloak")
    page.wait_for_selector("#username")
    if name_prefix:
        page.fill("#username", user)
        shot(page, f"{name_prefix}_keycloak_login", full=False)
    page.fill("#username", user)
    page.fill("#password", password)
    page.click("#kc-login")
    for _ in range(100):
        if page.url.startswith(APP):
            return
        if page.locator("[name=accept]").count():
            if name_prefix:
                shot(page, f"{int(name_prefix) + 1}_consent", full=False)
            page.click(f"[name={consent}]")
            page.wait_for_url(f"{APP}/**")
            page.wait_for_load_state("networkidle")
            return
        time.sleep(0.1)
    raise RuntimeError("logowanie nie zakończyło się: " + page.url)


with sync_playwright() as p:
    browser = p.chromium.launch()
    vp = {"width": 1240, "height": 820}

    # ------------------------------------------------ Zadanie 1: rejestracja w Keycloaku
    adm = browser.new_context(viewport={"width": 1400, "height": 900})
    pg = adm.new_page()
    pg.goto(f"{KC}/admin/master/console/")
    pg.fill("#username", "admin")
    pg.fill("#password", "admin")
    pg.click("#kc-login")
    pg.wait_for_load_state("networkidle")
    time.sleep(4)
    tok = requests.post(f"{KC}/realms/master/protocol/openid-connect/token",
                        data={"client_id": "admin-cli", "username": "admin", "password": "admin",
                              "grant_type": "password"}).json()["access_token"]
    cid = requests.get(f"{KC}/admin/realms/pbksi/clients?clientId=pbksi-webapp",
                       headers={"Authorization": f"Bearer {tok}"}).json()[0]["id"]
    for path, name, jump in [(f"clients/{cid}/settings", "01_kc_client_settings", None),
                             (f"clients/{cid}/settings", "01b_kc_client_capability", "Capability config"),
                             (f"clients/{cid}/credentials", "02_kc_client_credentials", None),
                             ("realm-settings/tokens", "03_kc_realm_refresh_tokens", "Refresh tokens"),
                             ("realm-settings/sessions", "04_kc_realm_sessions", None),
                             ("roles", "05_kc_roles", None),
                             ("users", "06_kc_users", None)]:
        pg.goto(f"{KC}/admin/master/console/#/pbksi/{path}")
        pg.wait_for_load_state("networkidle")
        time.sleep(2.5)
        if pg.locator("text=Could not find").count():
            pg.reload()
            pg.wait_for_load_state("networkidle")
            time.sleep(3)
        if jump:
            pg.get_by_role("heading", name=jump, exact=True).first.evaluate(
                "e => e.scrollIntoView({block: 'start'})")
            time.sleep(1.5)
        pg.screenshot(path=str(OUT / f"{name}.png"), full_page=False)
        print("zrzut:", name)
    adm.close()

    # ------------------------------------------------ anna (admin)
    a = browser.new_context(viewport=vp)
    pa = a.new_page()
    pa.goto(APP)
    shot(pa, "10_app_start", full=False)
    kc_login(pa, "anna", "anna123", name_prefix="11")
    shot(pa, "13_home_admin")
    pa.goto(f"{APP}/zasob/oceny")
    shot(pa, "14_oceny_anna")
    pa.goto(f"{APP}/zasob/uzytkownicy")
    shot(pa, "15_uzytkownicy_admin")
    pa.goto(f"{APP}/tokeny")
    shot(pa, "16_tokeny")
    # zawartość bazy sesji aplikacji w tej chwili (anna zalogowana) - tokeny są zaszyfrowane
    dump = subprocess.run(["docker", "exec", "lab3-app", "python", "-c", DUMP_DB], capture_output=True, text=True)
    (OUT.parent / "logs" / "sessions_db.log").write_text(dump.stdout)
    print(dump.stdout)
    cookies = a.cookies()
    print("ciasteczka aplikacji:", [(c["name"], c["httpOnly"], c["sameSite"]) for c in cookies if c["domain"] == "localhost"])

    # Atak CSRF z obcej strony: formularz wysyłany automatycznie na /wyloguj
    evil = a.new_page()
    evil.set_content("""<html><body><h1>Wygrałeś nagrodę!</h1>
      <form id=f method=post action="http://localhost:5000/wyloguj"></form>
      <script>document.getElementById('f').submit()</script></body></html>""")
    evil.wait_for_url(f"{APP}/wyloguj")
    shot(evil, "30_csrf_logout_blocked", full=False)
    evil.close()
    # to samo z tej samej przeglądarki (z ciasteczkiem sesji), ale bez tokenu CSRF
    r = a.request.post(f"{APP}/odswiez", form={"csrf_token": "zgadywany"})
    print("POST /odswiez bez poprawnego tokenu CSRF ->", r.status)

    # ------------------------------------------------ ewa (bez roli) + odmowa zgody
    e = browser.new_context(viewport=vp)
    pe = e.new_page()
    kc_login(pe, "ewa", "ewa123", consent="cancel")
    shot(pe, "31_consent_denied", full=False)
    kc_login(pe, "ewa", "ewa123")
    shot(pe, "24_home_guest")
    pe.goto(f"{APP}/zasob/oceny")
    shot(pe, "25_guest_forbidden", full=False)
    # administrator kończy sesje ewy w Keycloaku -> jej refresh token przestaje działać
    tok = requests.post(f"{KC}/realms/master/protocol/openid-connect/token",
                        data={"client_id": "admin-cli", "username": "admin", "password": "admin",
                              "grant_type": "password"}).json()["access_token"]
    uid = requests.get(f"{KC}/admin/realms/pbksi/users?username=ewa&exact=true",
                       headers={"Authorization": f"Bearer {tok}"}).json()[0]["id"]
    r = requests.post(f"{KC}/admin/realms/pbksi/users/{uid}/logout", headers={"Authorization": f"Bearer {tok}"})
    print("admin: zakończenie sesji ewy w Keycloaku ->", r.status_code)

    # Odświeżanie: poczekaj, aż access token (120 s) wygaśnie
    if WAIT_EXPIRY:
        print("czekam 125 s na wygaśnięcie access tokenów...")
        time.sleep(125)
        pa.goto(f"{APP}/zasob/oceny")   # aplikacja sama odświeży token
        pa.goto(f"{APP}/tokeny")
        shot(pa, "17_tokeny_po_odswiezeniu")
        pe.goto(f"{APP}/zasob/oceny")   # refresh token ewy jest już nieważny
        shot(pe, "26_sesja_wygasla", full=False)
    e.close()
    pa.click("text=Odśwież access token teraz")
    shot(pa, "18_tokeny_reczne_odswiezenie", full=False)

    # ------------------------------------------------ jan (user)
    j = browser.new_context(viewport=vp)
    pj = j.new_page()
    kc_login(pj, "jan", "jan123")
    shot(pj, "20_home_user")
    pj.goto(f"{APP}/zasob/oceny")
    shot(pj, "21_oceny_jan")
    pj.goto(f"{APP}/zasob/uzytkownicy")
    shot(pj, "22_user_forbidden", full=False)
    pj.goto(f"{APP}/audyt")
    pj.goto(APP)
    pj.click("text=Wyloguj")
    shot(pj, "23_wylogowano", full=False)
    j.close()


    # ------------------------------------------------ CSRF na /callback (zły state)
    x = browser.new_context(viewport=vp)
    px = x.new_page()
    px.goto(APP)
    px.click("text=Zaloguj przez Keycloak")       # sesja z oczekującym state
    px.wait_for_selector("#username")
    px.goto(f"{APP}/callback?code=kod-atakujacego&state=spreparowany")
    shot(px, "32_callback_bad_state", full=False)
    x.close()

    # ------------------------------------------------ anna: audyt + wylogowanie
    pa.goto(f"{APP}/audyt")
    shot(pa, "40_audyt")
    pa.goto(APP)
    pa.click("text=Wyloguj")
    pa.goto(f"{APP}/tokeny")
    print("po wylogowaniu /tokeny ->", pa.url)
    a.close()
    browser.close()
