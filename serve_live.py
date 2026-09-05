"""Start FastAPI server and Cloudflare Public Tunnel for worldwide access."""

import os
import sys
import subprocess
import threading
import time
import re

CLOUDFLARED_PATH = r"C:\Users\nakul\AppData\Local\Microsoft\WinGet\Packages\Cloudflare.cloudflared_Microsoft.Winget.Source_8wekyb3d8bbwe\cloudflared.exe"
PYTHON_PATH = r"C:\Users\nakul\AppData\Local\Programs\Python\Python312\python.exe"
PROJECT_DIR = r"C:\Users\nakul\.gemini\antigravity\scratch\ai-code-reviewer"
URL_FILE = os.path.join(PROJECT_DIR, "LIVE_URL.txt")


def start_uvicorn():
    """Start uvicorn server."""
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, log_level="warning")


def main():
    print("[*] Starting local AI Code Reviewer server on port 8000...")
    uvicorn_thread = threading.Thread(target=start_uvicorn, daemon=True)
    uvicorn_thread.start()

    time.sleep(2)

    print("[*] Launching Cloudflare Tunnel for worldwide access...")
    cmd = [CLOUDFLARED_PATH, "tunnel", "--url", "http://127.0.0.1:8000"]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    tunnel_url = None
    for line in iter(proc.stdout.readline, ""):
        print(line, end="")
        match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
        if match and not tunnel_url:
            tunnel_url = match.group(0)
            print("\n" + "=" * 65)
            print(f"  [+] YOUR APP IS LIVE WORLDWIDE AT:")
            print(f"  --> {tunnel_url}")
            print("=" * 65 + "\n")
            with open(URL_FILE, "w", encoding="utf-8") as f:
                f.write(tunnel_url.strip())
            sys.stdout.flush()

    proc.wait()


if __name__ == "__main__":
    main()
