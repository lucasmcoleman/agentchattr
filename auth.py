"""Built-in authentication for agentchattr: argon2 users, signed session cookies, rate limiting.

Design (night build 2026-09-17, per Lucas: login in-app instead of Authelia):

- Loopback trustedness is PRESERVED: local requests keep the existing in-band session-token
  behavior (launcher scripts grep the index for it; MCP/agent auth is untouched).
- "External" means the request carries X-Forwarded-Proto: https — set by our own SWAG
  nginx before the SSH tunnel. The app binds loopback, so only nginx can legitimately
  add that header over the public path. A local process forging it only gets the STRICTER
  external treatment (login gate) — the discriminator is fail-closed.
- Password hashes: data/users.json (argon2id via argon2-cffi). Bootstrap password from
  env AGENTCHAT_BOOTSTRAP_PASSWORD, or generated on first start and written to
  data/INITIAL-CREDENTIALS.txt (owner-only perms; never logged).
- Session cookie: "username|expiry|nonce|HMAC" signed with a per-install secret kept in
  data/.auth_secret. Stateless verification; tamper or expiry rejected.
- Rate limit: per (ip, username) in-memory counter; exponential delay, then lockout
  window after repeated failures.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _AVAILABLE = True
except ImportError:  # pragma: no cover - degrade loudly at use time
    _AVAILABLE = False

COOKIE_NAME = "agentchattr_session"
SESSION_TTL_SECONDS = 14 * 24 * 3600  # 14 days

# Rate limiting: after N consecutive failures, wait growing time; hard-lock after M.
_FAIL_THRESHOLD = 3
_LOCK_THRESHOLD = 8


class RateLimiter:
    """In-memory per-(ip,user) login throttle. Not durable across restarts by design."""

    def __init__(self) -> None:
        self._fails: dict[tuple[str, str], tuple[int, float]] = {}  # key -> (count, last_ts)

    def allow(self, ip: str, user: str) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds)."""
        key = (ip or "", user or "")
        count, last = self._fails.get(key, (0, 0.0))
        now = time.monotonic()
        if count >= _LOCK_THRESHOLD:
            # Hard lockout: 15 minutes since last attempt before trying again.
            if now - last < 900:
                return False, 900 - (now - last)
            self._fails.pop(key, None)
            return True, 0.0
        if count >= _FAIL_THRESHOLD:
            delay = min(60.0, 2.0 ** (count - _FAIL_THRESHOLD + 1))
            if now - last < delay:
                return False, delay - (now - last)
        return True, 0.0

    def record_failure(self, ip: str, user: str) -> None:
        key = (ip or "", user or "")
        count, _ = self._fails.get(key, (0, 0.0))
        self._fails[key] = (count + 1, time.monotonic())

    def record_success(self, ip: str, user: str) -> None:
        self._fails.pop((ip or "", user or ""), None)


class AuthManager:
    def __init__(self, data_dir: Path) -> None:
        if not _AVAILABLE:
            raise RuntimeError(
                "auth requested but argon2-cffi is not installed "
                "(pip install argon2-cffi)"
            )
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.users_path = self.data_dir / "users.json"
        self.secret_path = self.data_dir / ".auth_secret"
        self.credentials_file = self.data_dir / "INITIAL-CREDENTIALS.txt"
        self.hasher = PasswordHasher()  # argon2id per current library defaults
        self.limiter = RateLimiter()
        self.secret = self._load_or_create_secret()
        self.generated_password: str | None = None  # set only by first-run bootstrap

    # ---------- bootstrap ----------

    def _load_or_create_secret(self) -> bytes:
        if self.secret_path.exists():
            return bytes.fromhex(self.secret_path.read_text("utf-8").strip())
        secret = secrets.token_bytes(32)
        self._write_private(self.secret_path, secret.hex() + "\n")
        return secret

    def _write_private(self, path: Path, content: str) -> None:
        path.write_text(content, "utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # Windows: owner-only via ACL inheritance under AppData; best-effort here

    def bootstrap(self, username: str = "lucas") -> str:
        """Ensure at least one user exists. Returns action taken: 'exists'|'env'|'generated'."""
        users = self._load_users()
        if users:
            return "exists"
        env_pw = os.environ.get("AGENTCHAT_BOOTSTRAP_PASSWORD", "").strip()
        if env_pw:
            self._save_user(username, env_pw)
            return "env"
        pw = secrets.token_urlsafe(15)  # ~20 chars, comfortable to type once
        self._save_user(username, pw)
        self.generated_password = pw
        self._write_private(
            self.credentials_file,
            f"agentchattr built-in auth — first-run credentials\n"
            f"username: {username}\n"
            f"password: {pw}\n"
            f"\nChange it from the login page after signing in (link provided),\n"
            f"or set AGENTCHAT_BOOTSTRAP_PASSWORD and re-bootstrap.\n"
            f"This file can be deleted once you've logged in.\n",
        )
        return "generated"

    # ---------- users (json store: {user: argon2_hash}) ----------

    def _load_users(self) -> dict:
        import json
        if not self.users_path.exists():
            return {}
        try:
            return json.loads(self.users_path.read_text("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _record_hash(rec) -> str:
        """Support both legacy plain-string hashes and versioned dict records."""
        if isinstance(rec, dict):
            return rec.get("h", "")
        return rec or ""

    @staticmethod
    def _record_version(rec) -> int:
        if isinstance(rec, dict):
            try:
                return int(rec.get("v", 0))
            except (TypeError, ValueError):
                return 0
        return 0

    def _user_version(self, username: str) -> int:
        return self._record_version(self._load_users().get(username))

    def _save_user(self, username: str, password: str, version: int | None = None) -> None:
        import json
        users = self._load_users()
        if version is None:
            version = self._record_version(users.get(username))
        users[username] = {"h": self.hasher.hash(password), "v": version}
        tmp = self.users_path.with_suffix(".tmp")
        self._write_private(tmp, json.dumps(users, indent=2))
        os.replace(tmp, self.users_path)

    def verify_password(self, username: str, password: str) -> bool:
        users = self._load_users()
        stored = self._record_hash(users.get(username))
        if not stored:
            # Constant-ish time: hash anyway so user enumeration via timing is muted.
            self.hasher.hash(password)
            return False
        try:
            self.hasher.verify(stored, password)
            # Transparent rehash on parameter upgrades (preserve session version):
            if self.hasher.check_needs_rehash(stored):
                self._save_user(username, password, version=self._record_version(users.get(username)))
            return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if not self.verify_password(username, old_password):
            return False
        if len(new_password) < 8:
            return False
        # Bump the session version so ALL previously issued cookies stop working.
        self._save_user(username, new_password, version=self._user_version(username) + 1)
        return True

    # ---------- session cookies ----------

    def make_session(self, username: str) -> str:
        expiry = int(time.time()) + SESSION_TTL_SECONDS
        nonce = secrets.token_hex(8)
        ver = self._user_version(username)
        base = f"{username}|{expiry}|{nonce}|{ver}"
        sig = hmac.new(self.secret, base.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{base}|{sig}"

    def verify_session(self, cookie_value: str | None) -> str | None:
        """Return the username for a valid unexpired signed cookie, else None.

        The session embeds the user's password version; a password change bumps it,
        which invalidates every cookie issued before the change (stateless revoke).
        """
        if not cookie_value:
            return None
        parts = cookie_value.split("|")
        if len(parts) != 5:
            return None
        username, expiry, nonce, ver, sig = parts
        base = f"{username}|{expiry}|{nonce}|{ver}"
        expected = hmac.new(self.secret, base.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            if int(expiry) < time.time():
                return None
        except ValueError:
            return None
        # Live version check: stale-version cookies are dead even if correctly signed.
        users = self._load_users()
        rec = users.get(username)
        if rec is None:
            return None
        if self._record_version(rec) != int(ver):
            return None
        return username


# ---------- request classification ----------

def is_external_http(request) -> bool:
    """External = arrived via our public HTTPS proxy.

    Our SWAG nginx sets X-Forwarded-Proto: https on the public server block before the
    SSH-tunnel Unix socket. Direct loopback use never carries it. A local process forging
    the header only gets the stricter login-gated path (fail-closed), never more access.
    """
    xfp = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    return xfp == "https"


def client_ip(request) -> str:
    # For rate limiting use the socket peer when loopback-visible; XFF is only trusted
    # chain-wise if a proxy sets it — nginx over a Unix socket sees the PC's IP, so
    # the socket peer is the honest value on this architecture.
    return request.client.host if request.client else "unknown"
