import requests

BHE_URL = "http://localhost:8080"
JWT = ""  # bearer token
asset_group_id = 2     # Owned

sids = [
    "S-1-5-21-",
]

payload = [{"selector_name": "Manual", "sid": sid, "action": "add"} for sid in sids]

r = requests.put(
    f"{BHE_URL}/api/v2/asset-groups/{asset_group_id}/selectors",
    headers={"Authorization": f"Bearer {JWT}", "Content-Type": "application/json"},
    json=payload,
    timeout=30,
)
r.raise_for_status()
print("OK", r.status_code)

import os
import json
import tempfile
import requests
from src.conn import DEFAULT_URI, DEFAULT_USER, DEFAULT_PASS

SESSION_PATH = os.path.join(tempfile.gettempdir(), "patchhound.session.json")


def _load_session():
    if not os.path.exists(SESSION_PATH):
        raise RuntimeError("No session found — run `auth` first.")
    try:
        with open(SESSION_PATH, "r") as f:
            data = json.load(f)
    except Exception:
        raise RuntimeError("Session file is invalid — re-run `auth`.")
    base_url = data.get("base_url")
    token = data.get("session_token")
    if not base_url or not token:
        raise RuntimeError("Session file missing base_url or session_token — re-run `auth`.")
    return base_url, token


def _redact_token(tok: str) -> str:
    if not tok:
        return "<missing>"
    return tok[:6] + "..." + tok[-6:] if len(tok) > 12 else tok[:3] + "..." + tok[-3:]


def _redact_secret(_: str) -> str:
    return "████████"


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


def _check_file(path: str, what: str):
    if not path:
        return
    if not os.path.exists(path):
        raise RuntimeError(f"{what} not found: {path}")
    if not os.path.isfile(path):
        raise RuntimeError(f"{what} is not a file: {path}")


def run(args, markers: dict, no_color: bool):
    verbose = getattr(args, "verbose", False)

    try:
        base_url, token = _load_session()
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return

    url = f"{base_url.rstrip('/')}/api/version"
    headers = {
        "accept": "application/json",
        "Prefer": "0",
        "Authorization": f"Bearer {token}",
    }

    if verbose:
        print(f"{markers['info']} Verifying token via {url}")
        redacted_headers = dict(headers)
        redacted_headers["Authorization"] = "Bearer " + _redact_token(token)
        print(f"{markers['info']} Headers:\n{json.dumps(redacted_headers, indent=2)}")

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(f"{markers['warn']} Request failed: {e}")
        return

    if verbose:
        print(f"{markers['info']} Response status: {resp.status_code}")
        try:
            pretty = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            print(f"{markers['info']} Response JSON:\n{pretty}")
        except ValueError:
            print(f"{markers['info']} Response (non-JSON):\n{resp.text}")

    if resp.status_code != 200:
        print(f"{markers['warn']} {_extract_error_message(resp)}")
        return

    if verbose:
        print(f"{markers['info']} Using session token: {_redact_token(token)}")
        print(f"{markers['info']} Base URL: {base_url}")
    else:
        print(f"{markers['ok']} JWT valid")

    clears = args.clears
    ntlm = args.ntlm
    kerberos = args.kerberos

    if not clears or (not ntlm and not kerberos):
        print(f"{markers['warn']} Usage error: --clears is required, plus at least one of --ntlm or --kerberos.")
        return

    if verbose:
        print(f"{markers['info']} Validating input files")
        print(f"{markers['info']} clears: {clears}")
        if ntlm:
            print(f"{markers['info']} ntlm: {ntlm}")
        if kerberos:
            print(f"{markers['info']} kerberos: {kerberos}")

    try:
        _check_file(clears, "Clears file")
        if ntlm:
            _check_file(ntlm, "NTLM file")
        if kerberos:
            _check_file(kerberos, "Kerberos file")
    except RuntimeError as e:
        print(f"{markers['warn']} {e}")
        return

    if verbose:
        print(f"{markers['info']} Neo4j defaults:")
        print(f"    uri={DEFAULT_URI}")
        print(f"    user={DEFAULT_USER}")
        print(f"    pass={_redact_secret(DEFAULT_PASS)}")

    try:
        from neo4j import GraphDatabase
    except Exception:
        print(f"{markers['warn']} Neo4j driver not installed. Install with: pip install neo4j")
        return

    try:
        driver = GraphDatabase.driver(DEFAULT_URI, auth=(DEFAULT_USER, DEFAULT_PASS))
        with driver.session() as session:
            _ = session.run("RETURN 1 AS ok").single()
        driver.close()
        print(f"{markers['ok']} Neo4j auth OK")
    except Exception as e:
        msg = str(e)
        if any(k in msg.lower() for k in ["auth", "unauthorized", "authentication"]):
            print(f"{markers['warn']} Neo4j auth failed (see src/conn.py)")
        else:
            print(f"{markers['warn']} Neo4j connection failed: {msg}")
        return

    if verbose:
        print(f"{markers['ok']} Inputs validated; ready to patch.")
