"""Launcher script for AI Code Reviewer & Security Auditor."""

import os
import sys
import webbrowser
import threading
import time
import socket


def find_free_port(start_port=8000):
    """Find an available TCP port starting from start_port."""
    port = start_port
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            res = sock.connect_ex(("127.0.0.1", port))
            if res != 0:
                return port
        port += 1
    return start_port


def open_browser(port):
    """Open default browser once the server is alive."""
    time.sleep(1.2)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Opening Cyber Security Dashboard: {url}")
    webbrowser.open(url)


def main():
    print("=" * 65)
    print("  AI Code Reviewer & Security Auditor")
    print("  OWASP Top 10 • Static Analysis • AI Auto-Remediation")
    print("=" * 65)

    port = find_free_port(8000)
    print(f"[*] Starting local server on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C in terminal to stop.")

    # Launch browser thread
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
