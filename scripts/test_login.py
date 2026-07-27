"""Start auth service and test login."""
import subprocess, sys, time, json, urllib.request
from pathlib import Path

backend_dir = str(Path(__file__).parent.parent / "backend")
service_dir = Path(__file__).parent.parent / "backend" / "services" / "auth_service"

env = {"PYTHONPATH": backend_dir, "PATH": ";".join([str(Path(sys.executable).parent), sys.path[0]])}

proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"],
    cwd=service_dir,
    env={**{k: str(v) for k, v in dict(env).items()}, **dict(env)},
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

time.sleep(5)

try:
    data = json.dumps({"email": "admin@socplatform.io", "password": "Admin123!"}).encode()
    req = urllib.request.Request(
        "http://localhost:8002/api/v1/auth/login",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    r = urllib.request.urlopen(req, timeout=5)
    resp = json.loads(r.read())
    print("Login OK, status:", r.status)
    print("User:", json.dumps(resp.get("user"), indent=2)[:200])
    token_preview = resp.get("access_token", "")[:20] + "..."
    print("Token preview:", token_preview)
except urllib.error.HTTPError as e:
    print("Error:", e.code, e.read().decode()[:500])
except Exception as e:
    print("Exception:", type(e).__name__, str(e)[:500])
finally:
    proc.terminate()
    proc.wait(timeout=5)
