import os
import json
import stat
import tempfile
from getpass import getpass
from urllib.parse import urljoin
import requests

SESSION_PATH = os.path.join(tempfile.gettempdir(), "patchhound.session.json")

def _normalize_base(url: str) -> str:
    url = url.strip()
    return url if url.endswith("/") else f"{url}/"


def _extract_error_message(resp) -> str:
    try:
        body = resp.json()
        errs = body.get("errors")
        if isinstance(errs, list) and errs:
            msg = errs[0].get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
    except ValueError:
        pass
    return "Error"


def _redact_token(tok: str) -> str:
    if not tok:
        return "<missing>"
    return tok[:6] + "..." + tok[-6:] if len(tok) > 12 else tok[:3] + "..." + tok[-3:]


def _redact_secret(_: str) -> str:
    return "████████"


def _atomic_write_json(payload: dict, path: str = SESSION_PATH):
    d = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", dir=d, delete=False) as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def run(args, markers: dict, no_color: bool):
    base = _normalize_base(args.url)
    username = args.username
    secret = args.password or getpass("Password: ")
    login_url = urljoin(base, "api/v2/login")

    payload = {"login_method": "secret", "username": username, "secret": secret}

    if args.verbose:
        redacted_payload = dict(payload)
        redacted_payload["secret"] = _redact_secret(secret)
        print(f"{markers['info']} Preparing login request")
        print(f"{markers['info']} URL: {login_url}")
        print(f"{markers['info']} JSON payload being sent:")
        print(json.dumps(redacted_payload, indent=2, ensure_ascii=False))
        print(f"{markers['info']} Sending request to BloodHound CE API...")

    try:
        resp = requests.post(
            login_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=15,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Request failed: {e}")

    if args.verbose:
        print(f"{markers['info']} Response status: {resp.status_code}")
        try:
            body = resp.json()
            redacted = body
            if isinstance(body, dict):
                if "data" in body and isinstance(body["data"], dict) and "session_token" in body["data"]:
                    redacted = dict(body)
                    redacted["data"] = dict(body["data"])
                    redacted["data"]["session_token"] = _redact_token(body["data"]["session_token"])
                elif "session_token" in body:
                    redacted = dict(body)
                    redacted["session_token"] = _redact_token(body["session_token"])
            print(f"{markers['info']} Response JSON:\n{json.dumps(redacted, indent=2, ensure_ascii=False)}")
        except ValueError:
            print(f"{markers['info']} Response (non-JSON):\n{resp.text}")

    if resp.status_code not in (200, 201):
        print(f"{markers['warn']} {_extract_error_message(resp)}")
        return

    try:
        top = resp.json()
    except ValueError:
        print(f"{markers['warn']} Error")
        return

    body = top.get("data", top) if isinstance(top, dict) else {}
    token = body.get("session_token")
    if not token:
        print(f"{markers['warn']} {_extract_error_message(resp)}")
        return

    _atomic_write_json({"base_url": base, "session_token": token})

    if args.verbose:
        print(f"{markers['ok']} session stored (tmp): {SESSION_PATH}")
        print(f"{markers['ok']} token: {_redact_token(token)}")
        print(f"{markers['ok']} Login successful")
    else:
        print(f"{markers['ok']} Success")
