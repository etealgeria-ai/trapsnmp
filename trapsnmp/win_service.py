"""Install or remove the Windows service from the console."""

from __future__ import annotations

import os
import subprocess
import sys
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


def control(action: str) -> dict:
    if os.name != "nt":
        raise ValueError("Start, stop, and delete are only available on Windows.")
    action = action.strip().lower()
    if action not in ("start", "stop", "delete"):
        raise ValueError("Use start, stop, or delete.")
    _CACHE["value"] = None
    current = _query()
    if action == "start":
        if current.get("running"):
            current["detail"] = "The Windows service is already running."
            return current
        if not current.get("installed"):
            return apply(True)
        _spawn([_sc(), "start", SERVICE])
        return _pending(
            "Starting trapsnmp. It is not in the Windows Start menu. Press Win+R, type services.msc, and open the service named trapsnmp."
        )
    if not current.get("installed"):
        current["detail"] = "The Windows service is not installed."
        return current
    if action == "stop":
        _spawn([_sc(), "stop", SERVICE])
        return _pending("Stopping the Windows service. This page closes if the service is serving it.")
    if os.environ.get("TRAPSNMP_SERVICE") == "1":
        _schedule_delete()
        _spawn([_sc(), "stop", SERVICE])
        return _pending("The service is stopping and will be deleted.")
    _spawn_powershell(
        "Stop-Service -Name trapsnmp -Force -ErrorAction SilentlyContinue; "
        "Start-Sleep -Seconds 4; sc.exe delete trapsnmp"
    )
    return _pending("Stopping and deleting the Windows service.")


def _pending(detail: str) -> dict:
    _CACHE["value"] = None
    result = _blank(detail, supported=True)
    result["pending"] = True
    return result


def _sc() -> str:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(root, "System32", "sc.exe")


def _spawn(argv: list[str]) -> None:
    if _is_admin():
        subprocess.Popen(argv, creationflags=_no_window(), close_fds=True)
        return
    exe, args = argv[0], argv[1:]
    joined = ",".join(_ps_quote(part) for part in args)
    subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Start-Process -FilePath {_ps_quote(exe)} -Verb RunAs -ArgumentList {joined}",
        ],
        creationflags=_no_window(),
    )


def _spawn_powershell(command: str) -> None:
    if _is_admin():
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command", command],
            creationflags=_no_window(),
            close_fds=True,
        )
        return
    pieces = ["-NoProfile", "-Command", command]
    joined = ",".join(_ps_quote(part) for part in pieces)
    subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Start-Process -FilePath powershell -Verb RunAs -ArgumentList {joined}",
        ],
        creationflags=_no_window(),
    )


def _schedule_delete() -> None:
    stamp = time.strftime("%H:%M", time.localtime(time.time() + 90))
    command = "cmd /c sc stop trapsnmp & ping -n 8 127.0.0.1 >nul & sc delete trapsnmp & schtasks /Delete /TN trapsnmp-delete /F"
    subprocess.Popen(
        [
            "schtasks",
            "/Create",
            "/TN",
            "trapsnmp-delete",
            "/TR",
            command,
            "/SC",
            "ONCE",
            "/ST",
            stamp,
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
        ],
        creationflags=_no_window(),
        close_fds=True,
    )


def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


SERVICE = "trapsnmp"


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
    _remember_python()
    _CACHE["value"] = None
    if _is_admin():
        subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            cwd=str(script.parent),
        )
        detail = (
            "Installing the service named trapsnmp. It will not appear in the Windows Start menu. Press Win+R, type services.msc, and look for trapsnmp. If this page is already running the gateway, close it so the service can take the ports."
            if enabled
            else "Stopping and removing the Windows service named trapsnmp."
        )
    else:
        _elevate(script)
        detail = (
            "Approve the Windows prompt. The service is named trapsnmp and is listed in services.msc, not in the Start menu. If the prompt was cancelled, Start does nothing."
            if enabled
            else "Approve the Windows prompt to stop and remove the service named trapsnmp."
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
        return _blank(_install_note("Not installed. Start registers a service named trapsnmp. Find it in services.msc, not in the Windows Start menu."), supported=True)
    parts = line.split()
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return _blank(_install_note("Not installed. Start registers a service named trapsnmp. Find it in services.msc, not in the Windows Start menu."), supported=True)
    running = parts[0] == "4"
    automatic = parts[1] == "2"
    if running:
        detail = "Running. The service name is trapsnmp. Open it from services.msc, not from the Windows Start menu."
    elif automatic:
        detail = "Installed. It starts at boot, and it is not running yet. Press Start to run it."
    else:
        detail = "Installed, but it does not start at boot. Press Start to run it."
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


def _remember_python() -> None:
    exe = sys.executable
    if not exe or not os.path.isfile(exe) or exe.lower().endswith("pythonservice.exe"):
        return
    target = _scripts() / "python.path"
    target.write_text(exe, encoding="ascii")


def _install_note(detail: str) -> str:
    log = _scripts().parent / "data" / "service-install.log"
    try:
        lines = [line.strip() for line in log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except OSError:
        return detail
    if not lines:
        return detail
    return detail + " Last install message: " + lines[-1]


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"
