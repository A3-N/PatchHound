from getpass import getpass
from urllib.parse import urljoin

import requests

from patchhound.api import (
    SESSION_PATH,
    extract_error_message,
    normalize_base_url,
    pretty_json,
    redact_secret,
    redact_token,
    save_session,
)


def run(args, markers: dict, no_color: bool):
    base = normalize_base_url(args.url)
    username = args.username
    secret = args.password or getpass("Password: ")
    login_url = urljoin(base, "api/v2/login")

    payload = {"login_method": "secret", "username": username, "secret": secret}

    if args.verbose:
        redacted_payload = dict(payload)
        redacted_payload["secret"] = redact_secret(secret)
        print(f"{markers['info']} Login request:")
        print(
            pretty_json(
                {
                    "method": "POST",
                    "url": login_url,
                    "payload": redacted_payload,
                }
            )
        )
        print(f"{markers['info']} Sending request to BloodHound CE API...")

    try:
        resp = requests.post(
            login_url,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Request failed: {e}")

    if args.verbose:
        status_marker = markers["ok"] if resp.status_code < 400 else markers["warn"]
        print(f"{status_marker} Response status: {resp.status_code}")
        try:
            body = resp.json()
            redacted = body
            if isinstance(body, dict):
                if (
                    "data" in body
                    and isinstance(body["data"], dict)
                    and "session_token" in body["data"]
                ):
                    redacted = dict(body)
                    redacted["data"] = dict(body["data"])
                    redacted["data"]["session_token"] = redact_token(body["data"]["session_token"])
                elif "session_token" in body:
                    redacted = dict(body)
                    redacted["session_token"] = redact_token(body["session_token"])
            print(f"{markers['info']} Response JSON:\n{pretty_json(redacted)}")
        except ValueError:
            print(f"{markers['info']} Response (non-JSON):\n{resp.text[:2000]}")

    if resp.status_code not in (200, 201):
        print(f"{markers['warn']} {extract_error_message(resp)}")
        return False

    try:
        top = resp.json()
    except ValueError:
        print(f"{markers['warn']} Error")
        return False

    body = top.get("data", top) if isinstance(top, dict) else {}
    if not isinstance(body, dict):
        body = {}
    token = body.get("session_token")
    if not isinstance(token, str) or not token:
        print(f"{markers['warn']} {extract_error_message(resp)}")
        return False

    save_session(base, token)

    if args.verbose:
        print(f"{markers['ok']} Session stored: {SESSION_PATH}")
        print(f"{markers['ok']} Token: {redact_token(token)}")
        print(f"{markers['ok']} Login successful")
    else:
        print(f"{markers['ok']} Success")
    return True
