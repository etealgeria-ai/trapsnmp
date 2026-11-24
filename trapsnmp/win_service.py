"""Install or remove the Windows service from the console."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

_CACHE: dict = {"at": 0.0, "value": None}


def _scripts() -> Path:
    return Path(__file__).resolve().parent.parent / "windows"


def _blank(detail: str, *, supported: bool = False) -> dict:
    return {
        "supported": supported,
        "installed": False,
        "running": False,
        "enabled": False,
        "pending": False,
        "detail": detail,
    }


def status() -> dict:
    if os.name != "nt":
        return _blank("Only Windows can run trapsnmp as a service.")
    now = time.monotonic()
    cached = _CACHE["value"]
    if cached is not None and now - _CACHE["at"] < 3:
        return dict(cached)
    value = _query()
    _CACHE["at"] = now
    _CACHE["value"] = value
    return dict(value)


def apply(enabled: bool) -> dict:
    if os.name != "nt":
        raise ValueError("Run as a service is only available on Windows.")
    script = _scripts() / ("install-service.ps1" if enabled else "remove-service.ps1")
    if not script.is_file():
        raise ValueError("The Windows service scripts are not in the windows folder.")
    if enabled and os.environ.get("TRAPSNMP_SERVICE") == "1" and status().get("running"):
        current = status()
        current["detail"] = "Already running as a Windows service."
        return current
    _CACHE["value"] = None
    if _is_admin():
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            cwd=str(script.parent),
        )
        detail = (
            "Installing the service. If this window is already running trapsnmp, close it so the service can take the ports."
            if enabled
            else "Stopping and removing the Windows service."
        )
    else:
        _elevate(script)
        detail = (
            "Approve the Windows prompt to install the service. Then close this copy so the service can use the ports."
            if enabled
            else "Approve the Windows prompt to stop and remove the service."
        )
    result = _blank(detail, supported=True)
    result["pending"] = True
    result["enabled"] = bool(enabled)
    return result


def _query() -> dict:
    command = (
        "$s = Get-Service -Name trapsnmp -ErrorAction SilentlyContinue; "
        "if (-not $s) { 'missing' } else { '{0} {1}' -f [int]$s.Status, [int]$s.StartType }"
    )
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _blank(f"Could not ask Windows about the service: {exc}", supported=True)
    text = (done.stdout or "").strip().splitlines()
    line = text[-1].strip() if text else ""
    if not line or line == "missing":
        return _blank("Not installed. Turn this on to register the trapsnmp service.", supported=True)
    parts = line.split()
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return _blank("Not installed. Turn this on to register the trapsnmp service.", supported=True)
    running = parts[0] == "4"
    automatic = parts[1] == "2"
    if running:
        detail = "Running as a Windows service. It starts at boot."
    elif automatic:
        detail = "Installed. It starts at boot, and it is not running yet."
    else:
        detail = "Installed, but it does not start at boot. Turn this on to set that."
    return {
        "supported": True,
        "installed": True,
        "running": running,
        "enabled": automatic,
        "pending": False,
        "detail": detail,
    }


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate(script: Path) -> None:
    pieces = [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    joined = ",".join(_ps_quote(piece) for piece in pieces)
    subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Start-Process -FilePath powershell -Verb RunAs -ArgumentList {joined}",
        ],
        cwd=str(script.parent),
    )


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"
