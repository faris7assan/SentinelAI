from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT_DIR = Path(__file__).resolve().parents[1]
DESKTOP_APP_MAIN = ROOT_DIR.parent / "SentinelAI_Desktop_App" / "desktop-app" / "main.py"
CONFIG_FILE = Path.home() / ".sentinelai" / "desktop_config.json"
BACKEND_URL = os.getenv("SENTINELAI_LOCAL_BACKEND_URL", "http://127.0.0.1:8000")


def write_desktop_config() -> None:
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if CONFIG_FILE.exists():
        try:
            existing = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing["backend_mode"] = "local"
    existing["backend_base_url"] = BACKEND_URL
    existing["base_urls"] = {name: BACKEND_URL for name in existing.get("base_urls", {}) or [
        "gateway", "auth", "logs", "detection", "ai", "soar", "threatintel",
        "alerts", "reports", "vpn", "honeypot", "sandbox", "cloud", "redteam",
        "agents", "metrics",
    ]}
    existing.setdefault("token", "")
    CONFIG_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def wait_for_backend(timeout_seconds: int = 20) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urlopen(f"{BACKEND_URL}/health", timeout=2) as response:
                if response.status == 200:
                    return
        except URLError:
            time.sleep(0.5)
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"Backend did not become ready at {BACKEND_URL}/health")


def start_backend() -> subprocess.Popen:
    command = [sys.executable, str(ROOT_DIR / "scripts" / "local_dev_backend.py")]
    return subprocess.Popen(command, cwd=str(ROOT_DIR))


def backend_is_ready() -> bool:
    try:
        with urlopen(f"{BACKEND_URL}/health", timeout=2) as response:
            return response.status == 200
    except Exception:
        return False


def start_desktop() -> subprocess.Popen:
    command = [sys.executable, str(DESKTOP_APP_MAIN)]
    return subprocess.Popen(command, cwd=str(DESKTOP_APP_MAIN.parent))


def main() -> int:
    parser = argparse.ArgumentParser(description="Start SentinelAI local dev mode")
    parser.add_argument("--backend-only", action="store_true", help="Start only the local backend")
    args = parser.parse_args()

    if not DESKTOP_APP_MAIN.exists():
        raise FileNotFoundError(f"Desktop app main not found: {DESKTOP_APP_MAIN}")

    write_desktop_config()
    backend = None
    if backend_is_ready():
        print(f"Backend already running at {BACKEND_URL}")
    else:
        backend = start_backend()

    try:
        wait_for_backend()
        print(f"Backend ready at {BACKEND_URL}")
        if args.backend_only:
            print("Backend-only mode enabled. Press Ctrl+C to stop.")
            if backend is None:
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    return 130
            backend.wait()
            return backend.returncode or 0

        desktop = start_desktop()
        print("Desktop app started in local mode.")
        try:
            desktop.wait()
        except KeyboardInterrupt:
            pass
        finally:
            if desktop.poll() is None:
                desktop.terminate()
                try:
                    desktop.wait(timeout=5)
                except Exception:
                    desktop.kill()
        return desktop.returncode or 0
    except KeyboardInterrupt:
        return 130
    finally:
        if backend and backend.poll() is None:
            backend.terminate()
            try:
                backend.wait(timeout=5)
            except Exception:
                backend.kill()


if __name__ == "__main__":
    raise SystemExit(main())
