"""Windows service for the trapsnmp gateway.

Installed by windows/install-service.bat. The service process starts
``python -m trapsnmp`` and stops that process when the service stops.
"""

from __future__ import annotations

import os
import subprocess
import sys

SERVICE_NAME = "trapsnmp"
SERVICE_DISPLAY = "trapsnmp"
SERVICE_DESCRIPTION = "Receives SNMP traps and publishes them on OPC UA."


def _root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _launch() -> subprocess.Popen:
    folder = _root()
    data = os.path.join(folder, "data")
    os.makedirs(data, exist_ok=True)
    env = os.environ.copy()
    env["TRAPSNMP_DATA"] = data
    env["PYTHONUNBUFFERED"] = "1"
    log = open(os.path.join(data, "trapsnmp.log"), "a", encoding="utf-8")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(
        [sys.executable, "-m", "trapsnmp"],
        cwd=folder,
        env=env,
        stdout=log,
        stderr=log,
        creationflags=flags,
    )


def main() -> None:
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
    except ImportError:
        sys.stderr.write("pywin32 is required. Run windows\\install-service.bat as administrator.\n")
        raise SystemExit(1)

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
            self._process = _launch()
            stopped = False
            while True:
                result = win32event.WaitForSingleObject(self._stop, 1000)
                if result == win32event.WAIT_OBJECT_0:
                    stopped = True
                    break
                if self._process.poll() is not None:
                    break
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self._process.kill()
            if not stopped:
                servicemanager.LogErrorMsg("trapsnmp exited; the service will restart")
                os._exit(1)
            servicemanager.LogInfoMsg("trapsnmp service stopped")

    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(TrapsnmpService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(TrapsnmpService)


if __name__ == "__main__":
    main()
