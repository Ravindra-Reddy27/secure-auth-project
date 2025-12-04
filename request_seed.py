#!/usr/bin/env python3
import requests
import json
import pathlib
import sys
import os

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
PUBLIC_KEY_PATH = "student_public.pem"   # relative path to your public key
OUTPUT_FILE = "encrypted_seed.txt"       # DO NOT commit this file to git

def read_public_key_for_api(pem_path: str) -> str:
    """
    Read PEM and return it WITH real newline characters.
    Raises FileNotFoundError or ValueError on problems.
    """
    p = pathlib.Path(pem_path)
    if not p.exists():
        raise FileNotFoundError(f"Public key file not found: {pem_path}")
    raw = p.read_text(encoding="utf-8", errors="strict")
    # Ensure final newline present (optional)
    if not raw.endswith("\n"):
        raw = raw + "\n"
    # Quick sanity check: must contain PEM markers
    if "-----BEGIN PUBLIC KEY-----" not in raw or "-----END PUBLIC KEY-----" not in raw:
        raise ValueError("Public key file missing BEGIN/END markers or is not a PEM public key.")
    return raw

def request_seed(student_id: str, github_repo_url: str, api_url: str = API_URL, public_pem_path: str = PUBLIC_KEY_PATH):
    try:
        public_key_text = read_public_key_for_api(public_pem_path)
    except (FileNotFoundError, ValueError) as e:
        print("Public key error:", e, file=sys.stderr)
        return False

    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_text
    }

    headers = {"Content-Type": "application/json"}
    try:
        # Use requests.post(json=...) so requests will serialize and escape newlines correctly
        resp = requests.post(api_url, json=payload, headers=headers, timeout=20)
    except requests.exceptions.RequestException as e:
        print("Network error:", e, file=sys.stderr)
        return False

    if resp.status_code != 200:
        print(f"Error: received HTTP {resp.status_code}", file=sys.stderr)
        print("Response body:", resp.text, file=sys.stderr)
        return False

    # parse JSON
    try:
        data = resp.json()
    except ValueError:
        print("Error: response is not valid JSON", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        return False

    if data.get("status") != "success" or "encrypted_seed" not in data:
        print("API returned error or no encrypted_seed:", json.dumps(data, indent=2), file=sys.stderr)
        return False

    encrypted_seed = data["encrypted_seed"]
    # Save to file (plain text). DO NOT add this file to git.
    try:
        pathlib.Path(OUTPUT_FILE).write_text(encrypted_seed, encoding="utf-8")
        # try to set restrictive permissions where supported
        try:
            os.chmod(OUTPUT_FILE, 0o600)
        except Exception:
            pass
    except Exception as e:
        print("Failed to write encrypted seed to file:", e, file=sys.stderr)
        return False

    print(f"Encrypted seed saved to {OUTPUT_FILE}")
    return True

if __name__ == "__main__":
    # Replace these values with your real student id and exact repo url
    student_id = "24P35A0530"
    github_repo_url = "https://github.com/Ravindra-Reddy27/secure-auth-project"
    ok = request_seed(student_id, github_repo_url)
    if not ok:
        sys.exit(1)
