"""
Sesje po stronie serwera z zaszyfrowanymi tokenami.

- Przeglądarka dostaje tylko losowy identyfikator sesji w ciasteczku HttpOnly + SameSite.
  Tokeny OAuth nigdy nie trafiają do przeglądarki (ani do JavaScriptu, ani do ciasteczek).
- W bazie SQLite zapisywany jest wyłącznie skrót SHA-256 identyfikatora sesji, więc wyciek bazy
  nie pozwala przejąć sesji przez podstawienie ciasteczka.
- Dane sesji (w tym access/refresh/id token) są szyfrowane algorytmem Fernet
  (AES-128-CBC + HMAC-SHA256) kluczem z zmiennej środowiskowej TOKEN_ENC_KEY.
"""
import hashlib
import json
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet, InvalidToken


class SessionStore:
    def __init__(self, path, key, ttl):
        self.path = path
        self.fernet = Fernet(key)
        self.ttl = ttl
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS sessions (
                              sid_hash TEXT PRIMARY KEY,
                              data     BLOB NOT NULL,
                              created  INTEGER NOT NULL,
                              expires  INTEGER NOT NULL)""")

    def _db(self):
        return sqlite3.connect(self.path)

    @staticmethod
    def _h(sid):
        return hashlib.sha256(sid.encode()).hexdigest()

    def create(self, data):
        sid = secrets.token_urlsafe(32)
        self.save(sid, data)
        return sid

    def save(self, sid, data):
        now = int(time.time())
        blob = self.fernet.encrypt(json.dumps(data).encode())
        with self._db() as db:
            db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)",
                       (self._h(sid), blob, now, now + self.ttl))

    def load(self, sid):
        if not sid:
            return None
        with self._db() as db:
            row = db.execute("SELECT data, expires FROM sessions WHERE sid_hash=?", (self._h(sid),)).fetchone()
        if not row:
            return None
        if row[1] < time.time():
            self.delete(sid)
            return None
        try:
            return json.loads(self.fernet.decrypt(row[0]))
        except InvalidToken:
            return None

    def delete(self, sid):
        with self._db() as db:
            db.execute("DELETE FROM sessions WHERE sid_hash=?", (self._h(sid),))

    def purge_expired(self):
        with self._db() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
