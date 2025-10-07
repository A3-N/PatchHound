import os
import json
import tempfile
import requests

DEFAULT_TOKEN_PATH = os.path.join(tempfile.gettempdir(), "patchhound.jwt")


def _load_jwt() -> str:
    if not os.path.exists(DEFAULT_TOKEN_PATH):
        raise RuntimeError("No session token found — please authenticate first.")
    with open(DEFAULT_TOKEN_PATH, "r") as f:
        token = f.read().strip()
    if not token:
        raise RuntimeError("Session token file is empty — please reauthenticate.")
    return token


def search(base_url: str, query: str, node_type: str = None, skip: int = 0, limit: int = 50,
           prefer: int = 0, verbose: bool = False):
    """
    Search BloodHound CE for nodes by name or ID.

    Args:
        base_url (str): Base URL (e.g. http://localhost:8080/)
        query (str): Search parameter (name or object ID)
        node_type (str, optional): Node type (User, Computer, Group, etc.)
        skip (int, optional): Pagination skip count
        limit (int, optional): Max results to return
        prefer (int, optional): 'Prefer' header (timeout hint)
        verbose (bool): Print detailed debug info
    """
    token = _load_jwt()
    url = f"{base_url.rstrip('/')}/api/v2/search"

    params = {"q": query}
    if node_type:
        params["type"] = node_type
    if skip:
        params["skip"] = skip
    if limit:
        params["limit"] = limit

    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Prefer": str(prefer),
    }

    if verbose:
        print("[*] Sending search request")
        print(f"[*] URL: {url}")
        print(f"[*] Query params: {json.dumps(params, indent=2)}")
        print(f"[*] Headers (sanitized): {{'Authorization': 'Bearer ****', 'Prefer': {prefer}}}")

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=20)
    except requests.RequestException as e:
        raise RuntimeError(f"Search request failed: {e}")

    if verbose:
        print(f"[*] Response status: {resp.status_code}")
        try:
            pretty = json.dumps(resp.json(), indent=2, ensure_ascii=False)
            print(f"[*] Response JSON:\n{pretty}")
        except ValueError:
            print(f"[*] Response (non-JSON):\n{resp.text}")

    if resp.status_code != 200:
        raise RuntimeError(f"Search failed with status {resp.status_code}")

    try:
        return resp.json()
    except ValueError:
        raise RuntimeError("Invalid JSON response from server")
