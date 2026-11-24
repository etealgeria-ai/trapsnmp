"""Windows service for the trapsnmp gateway.

Installed by windows/install-service.bat. The service process starts
``pythonw -m trapsnmp`` and starts it again if that process exits.
Closing a console window is not required, and it does not stop the web server.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

SERVICE_NAME = "trapsnmp"
SERVICE_DISPLAY = "trapsnmp"
SERVICE_DESCRIPTION = "Receives SNMP traps and publishes them on OPC UA."


def _root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _log_path() -> str:
    return os.path.join(_root(), "data", "trapsnmp.log")


def _note(text: str) -> None:
    try:
        os.makedirs(os.path.dirname(_log_path()), exist_ok=True)
        with open(_log_path(), "a", encoding="utf-8") as handle:
            handle.write(time.strftime("%Y-%m-%d %H:%M:%S ") + text + "\n")
    except OSError:
        pass


def _python_executable() -> str:
    candidates: list[str] = []
    path_file = os.path.join(os.path.dirname(__file__), "python.path")
    if os.path.isfile(path_file):
        with open(path_file, encoding="ascii", errors="ignore") as handle:
            saved = handle.read().strip().strip('"')
        if saved:
            candidates.append(saved)
    executable = sys.executable
    if executable.lower().endswith("pythonservice.exe"):
        prefix = os.path.abspath(os.path.join(os.path.dirname(executable), "..", "..", ".."))
        candidates.append(os.path.join(prefix, "python.exe"))
    else:
        candidates.append(executable)
    for candidate in candidates:
        if not candidate or not os.path.isfile(candidate):
            continue
        folder = os.path.dirname(candidate)
        windowless = os.path.join(folder, "pythonw.exe")
        # pythonw has no console, so closing a window cannot stop the web server.
        if os.path.isfile(windowless):
            return windowless
        if not candidate.lower().endswith("pythonservice.exe"):
            return candidate
    raise RuntimeError("Python was not found. Run windows\\install-service.bat again as administrator.")


def _launch() -> subprocess.Popen:
    folder = _root()
    data = os.path.join(folder, "data")
    os.makedirs(data, exist_ok=True)
    python = _python_executable()
    env = os.environ.copy()
    env["TRAPSNMP_DATA"] = data
    env["PYTHONUNBUFFERED"] = "1"
    env["TRAPSNMP_SERVICE"] = "1"
    env["PYTHONPATH"] = folder + os.pathsep + env.get("PYTHONPATH", "")
    log = open(_log_path(), "a", encoding="utf-8")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    # DETACHED_PROCESS and CREATE_NO_WINDOW cannot be combined. Prefer no console.
    if getattr(subprocess, "CREATE_NO_WINDOW", 0):
        flags = subprocess.CREATE_NO_WINDOW
    _note(f"service starting {python} -m trapsnmp")
    return subprocess.Popen(
        [python, "-m", "trapsnmp"],
        cwd=folder,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        creationflags=flags,
    )


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


if win32serviceutil is not None:

    class TrapsnmpService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop = win32event.CreateEvent(None, 0, 0, None)
            self._process = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop)

        def SvcDoRun(self):
            servicemanager.LogInfoMsg("trapsnmp service starting")
            os.chdir(_root())
            while True:
                try:
                    self._process = _launch()
                except Exception as exc:
                    _note(f"service could not start the gateway: {exc}")
                    servicemanager.LogErrorMsg(f"trapsnmp could not start: {exc}")
                    if win32event.WaitForSingleObject(self._stop, 5000) == win32event.WAIT_OBJECT_0:
                        break
                    continue
                restart = False
                while True:
                    result = win32event.WaitForSingleObject(self._stop, 1000)
                    if result == win32event.WAIT_OBJECT_0:
                        restart = False
                        break
                    code = self._process.poll()
                    if code is not None:
                        _note(f"gateway exited with code {code}; the service is starting it again")
                        restart = True
                        break
                if self._process is not None and self._process.poll() is None:
                    self._process.terminate()
                    try:
                        self._process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        self._process.kill()
                if not restart:
                    break
                time.sleep(2)
            servicemanager.LogInfoMsg("trapsnmp service stopped")


def main() -> None:
    if win32serviceutil is None:
        sys.stderr.write("pywin32 is required. Run windows\\install-service.bat as administrator.\n")
        raise SystemExit(1)
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TrapsnmpService)
        servicemanager.StartServiceCtrlDispatcher()
        return
    # Running this file directly would record the class as __main__.TrapsnmpService,
    # which the service host cannot import. The windows folder is on PYTHONPATH.
    win32serviceutil.HandleCommandLine(
        TrapsnmpService,
        serviceClassString="trapsnmp_service.TrapsnmpService",
    )


if __name__ == "__main__":
    main()
