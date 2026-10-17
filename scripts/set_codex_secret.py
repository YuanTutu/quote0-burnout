"""Link a dashboard-only Codex login to the GitHub Actions workflow.

Run AFTER completing a dedicated device login (independent token chain —
never the local CLI's ~/.codex/auth.json, whose refresh token rotates and
would be invalidated by the workflow's refreshes):

    # 1. in one terminal (browser approval; writes auth.json under CODEX_HOME):
    set CODEX_HOME=E:\\Code\\Dot\\quote0-burnout\\tmp\\codex-dashboard-home
    codex login --device-auth

    # 2. then:
    python scripts/set_codex_secret.py --repo YuanTutu/quote0-burnout --dispatch

Reads refresh_token + account_id from that auth.json, uploads them as the
repo's CODEX_REFRESH_TOKEN / CODEX_ACCOUNT_ID secrets (GitHub API, using the
git credential store's PAT), and optionally triggers a verification run.
Secret values are never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

from nacl import encoding, public


def _die(msg: str) -> None:
    print(f"set_codex_secret: {msg}", file=sys.stderr)
    sys.exit(1)


def github_token() -> str:
    cred = subprocess.run(
        ["git", "credential", "fill"],
        input=b"protocol=https\nhost=github.com\n\n",
        capture_output=True,
    ).stdout.decode()
    for line in cred.splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    _die("no GitHub credential in git credential store (run a git push once, "
         "or install gh and `gh auth login`)")


def api(repo: str, token: str, method: str, path: str, body: bytes | None = None) -> tuple[int, dict | bytes]:
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{path}",
        method=method,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def put_secret(repo: str, token: str, name: str, value: str) -> None:
    status, key = api(repo, token, "GET", "actions/secrets/public-key")
    if status != 200:
        _die(f"fetch public key failed HTTP {status}: {key if isinstance(key, bytes) else key.get('message')}")
    sealed = public.SealedBox(public.PublicKey(key["key"].encode(), encoding.Base64Encoder()))
    body = json.dumps({
        "encrypted_value": base64.b64encode(sealed.encrypt(value.encode())).decode(),
        "key_id": key["key_id"],
    }).encode()
    status, resp = api(repo, token, "PUT", f"actions/secrets/{name}", body)
    if status not in (201, 204):
        _die(f"set secret {name} failed HTTP {status}: {resp}")
    print(f"secret {name}: updated")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="YuanTutu/quote0-burnout")
    ap.add_argument("--auth-json",
                    default=str(Path(__file__).resolve().parent.parent / "tmp" / "codex-dashboard-home" / "auth.json"),
                    help="auth.json from the dashboard login session")
    ap.add_argument("--dispatch", action="store_true", help="trigger a verification workflow run")
    args = ap.parse_args()

    path = Path(args.auth_json)
    if not path.exists():
        _die(f"{path} not found — complete `CODEX_HOME=... codex login --device-auth` first")
    auth = json.loads(path.read_text(encoding="utf-8"))
    tokens = auth.get("tokens", {})
    refresh_token = tokens.get("refresh_token", "")
    account_id = tokens.get("account_id", "")
    if not refresh_token:
        _die("auth.json has no refresh_token")

    tok = github_token()
    put_secret(args.repo, tok, "CODEX_REFRESH_TOKEN", refresh_token)
    if account_id:
        put_secret(args.repo, tok, "CODEX_ACCOUNT_ID", account_id)

    # drop any stale encrypted state so the next run re-seeds from the new chain
    status, resp = api(args.repo, tok, "GET", "contents/state/codex_tokens.json.enc")
    if status == 200:
        sha = resp.get("sha")
        s2, _ = api(args.repo, tok, "DELETE", f"contents/state/codex_tokens.json.enc",
                    json.dumps({"message": "reset codex state for re-link", "sha": sha}).encode())
        print(f"stale encrypted state removed (HTTP {s2})")

    if args.dispatch:
        status, resp = api(args.repo, tok, "POST", "actions/workflows/refresh.yml/dispatches", b"{}")
        print(f"workflow dispatch: HTTP {status}"
              + ("" if status == 204 else f" — {resp}"))
        if status != 204:
            sys.exit(1)


if __name__ == "__main__":
    main()
