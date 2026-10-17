"""Refresh the Codex OAuth token for the GitHub Actions dashboard run.

Why this exists: the wham/usage endpoint needs a ChatGPT-account access token
that expires after ~10 days, and OpenAI's OAuth server rotates the refresh
token on every use (a consumed refresh token can never be replayed). A
stateless Actions runner therefore has to (1) refresh, (2) persist the NEW
refresh token somewhere the next run can read.

State handling: the token pair is kept AES-encrypted (openssl aes-256-cbc,
key from the CODEX_STATE_KEY secret) in STATE_FILE inside the repo; the
workflow commits the re-encrypted file back after each refresh. The seed
refresh token comes from the CODEX_REFRESH_TOKEN secret (an independent
`codex login --device-auth` session, NOT the local CLI's chain — two
consumers on one rotating chain invalidate each other).

Outputs: appends CODEX_ACCESS_TOKEN / CODEX_ACCOUNT_ID to $GITHUB_ENV so
display.py picks them up without either value ever appearing in logs.

Exits non-zero with a classified, actionable message on permanent failures
(refresh token reused / expired / revoked).
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

AUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
# Same public client_id the codex CLI itself uses (codex-rs login/src/auth/manager.rs).
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

# Refresh when the access token has less than this left (it lives ~10 days;
# hourly runs then refresh roughly every 9 days and commit state ~4x/month).
REFRESH_MARGIN_SECONDS = 6 * 3600


def _die(msg: str, code: int = 1) -> None:
    print(f"gh_refresh_codex_token: {msg}", file=sys.stderr)
    sys.exit(code)


def _openssl(args: list[str], data: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["openssl", *args, "-pass", "env:CODEX_STATE_KEY"],
        input=data,
        capture_output=True,
    )
    if proc.returncode != 0:
        _die(f"openssl {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def load_state(path: Path) -> dict | None:
    if not path.exists():
        return None
    plain = _openssl(["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", str(path)])
    try:
        return json.loads(plain)
    except json.JSONDecodeError:
        _die(f"{path} is not valid encrypted JSON (wrong CODEX_STATE_KEY?)")
        return None  # unreachable


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _openssl(
        ["enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-out", str(path)],
        json.dumps(state).encode(),
    )
    if not path.exists():
        _die(f"openssl did not write {path}")


def jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def token_seconds_left(access_token: str) -> float | None:
    exp = jwt_payload(access_token).get("exp")
    return (exp - time.time()) if isinstance(exp, (int, float)) else None


def account_id_from_id_token(id_token: str | None, fallback: str) -> str:
    if not id_token:
        return fallback
    auth = jwt_payload(id_token).get("https://api.openai.com/auth") or {}
    return auth.get("chatgpt_account_id") or fallback


def refresh(refresh_token: str) -> dict:
    r = requests.post(
        AUTH_TOKEN_URL,
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if r.status_code != 200:
        try:
            err = r.json().get("error", "")
            code = (err.get("code") or err.get("error")) if isinstance(err, dict) else (err or r.text[:200])
        except Exception:
            code = r.text[:200]
        hints = {
            "refresh_token_reused": "refresh token was already used by another run — re-link with scripts/set_codex_secret.py",
            "refresh_token_expired": "refresh token expired — re-link with scripts/set_codex_secret.py",
            "refresh_token_invalidated": "refresh token revoked — re-link with scripts/set_codex_secret.py",
            "token_expired": "refresh token expired — re-link with scripts/set_codex_secret.py",
            "invalid_grant": "grant rejected — re-link with scripts/set_codex_secret.py",
        }
        permanent = r.status_code in (400, 401, 403)
        _die(f"token refresh failed (HTTP {r.status_code}): {code}. "
             f"{hints.get(code, 're-run the workflow' if not permanent else 're-link with scripts/set_codex_secret.py')}")
    out = r.json()
    if not out.get("access_token") or not out.get("refresh_token"):
        _die(f"refresh response missing tokens: keys={sorted(out)}")
    return out


def main() -> None:
    state_file = Path(os.environ.get("CODEX_STATE_FILE", "state/codex_tokens.json.enc"))
    seed_refresh = os.environ.get("CODEX_REFRESH_TOKEN", "").strip()
    seed_account = os.environ.get("CODEX_ACCOUNT_ID", "").strip()
    if not os.environ.get("CODEX_STATE_KEY"):
        _die("CODEX_STATE_KEY (env/secret) not set")

    state = load_state(state_file)
    if state is None:
        if not seed_refresh:
            _die("no encrypted state and no CODEX_REFRESH_TOKEN secret — "
                 "run a dashboard `codex login --device-auth` session and "
                 "scripts/set_codex_secret.py once (see README GitHub section)")
        print("first run: seeding state from CODEX_REFRESH_TOKEN secret")
        tokens = refresh(seed_refresh)
        state = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "account_id": account_id_from_id_token(tokens.get("id_token"), seed_account),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        save_state(state_file, state)
        print("state seeded and encrypted")
    else:
        left = token_seconds_left(state.get("access_token", ""))
        if left is None:
            left = 0.0  # opaque token: safe side, refresh
        if left > REFRESH_MARGIN_SECONDS:
            print(f"access token still valid for {left/3600:.1f}h — no refresh needed")
        else:
            print(f"access token expiring in {left/3600:.1f}h — refreshing")
            tokens = refresh(state["refresh_token"])
            state.update(
                access_token=tokens["access_token"],
                refresh_token=tokens["refresh_token"],
                account_id=account_id_from_id_token(tokens.get("id_token"),
                                                    state.get("account_id", seed_account)),
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
            save_state(state_file, state)
            print("state refreshed and re-encrypted")

    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a", encoding="utf-8") as f:
            f.write(f"CODEX_ACCESS_TOKEN<<__EOF__\n{state['access_token']}\n__EOF__\n")
            if state.get("account_id"):
                f.write(f"CODEX_ACCOUNT_ID<<__EOF__\n{state['account_id']}\n__EOF__\n")
    exp = token_seconds_left(state["access_token"])
    print(f"access token ready (valid for {exp/3600:.1f}h)" if exp
          else "access token ready")


if __name__ == "__main__":
    main()
