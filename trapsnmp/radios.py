"""Poll a GE MDS Orbit LN master for connected remote radios.

The master keeps one row per remote in mIfLnStatusConnRemTable
(1.3.6.1.4.1.4130.10.2.5.1.2.2.1). The index is ifIndex plus the remote
MAC. Column 2 is the remote IP and column 6 is RSSI.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulkWalkCmd,
    walkCmd,
)

log = logging.getLogger("trapsnmp.radios")

ENTRY = "1.3.6.1.4.1.4130.10.2.5.1.2.2.1"
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")
_MAX_REMOTES = 256
CONFIG_PATH = Path("/workspace/data/ge-master.json")


def parse_index(suffix: str) -> tuple[int, str] | None:
    parts = suffix.split(".")
    if len(parts) < 7 or not all(part.isdigit() for part in parts[:7]):
        return None
    if_index = int(parts[0])
    mac = ":".join(f"{int(part) & 0xFF:02X}" for part in parts[1:7])
    return if_index, mac


def split_instance(oid: str) -> tuple[str, str] | None:
    text = oid.lstrip(".")
    prefix = ENTRY + "."
    if not text.startswith(prefix):
        return None
    column, _, index = text[len(prefix) :].partition(".")
    if not column.isdigit() or not index:
        return None
    return column, index


def _as_int(value) -> int | None:
    text = str(value).strip()
    if text.startswith("-") or text.isdigit():
        try:
            return int(text)
        except ValueError:
            return None
    return None


def _as_text(value) -> str:
    raw = bytes(value) if not isinstance(value, str) else b""
    if raw and all(32 <= byte < 127 for byte in raw):
        return raw.decode("ascii").strip()
    text = str(value).strip().strip('"')
    if text.lower().startswith("0x"):
        return ""
    return text


def _as_ip(value) -> str:
    text = str(value).strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return text
    raw = bytes(value) if not isinstance(value, str) else b""
    if len(raw) == 4:
        return ".".join(str(byte) for byte in raw)
    return text or "—"


def rows_from_binds(binds: list[tuple[str, object]]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for oid, value in binds:
        split = split_instance(oid)
        if split is None:
            continue
        column, index = split
        parsed = parse_index(index)
        if parsed is None:
            continue
        if_index, mac = parsed
        row = grouped.setdefault(
            index,
            {
                "ifIndex": if_index,
                "mac": mac,
                "key": mac.replace(":", ""),
                "ip": "—",
                "rssi": None,
                "downRssi": None,
                "evm": None,
                "name": "",
                "link": "",
            },
        )
        if column == "2":
            row["ip"] = _as_ip(value)
        elif column == "4":
            number = _as_int(value)
            row["link"] = "" if number is None else str(number)
        elif column == "6":
            row["rssi"] = _as_int(value)
        elif column == "7":
            row["evm"] = _as_int(value)
        elif column == "19":
            row["name"] = _as_text(value)
        elif column == "23":
            row["downRssi"] = _as_int(value)
    rows = list(grouped.values())
    rows.sort(key=lambda item: (item["ifIndex"], item["mac"]))
    return rows[:_MAX_REMOTES]


class OrbitMaster:
    def __init__(self, on_update) -> None:
        self.host = "192.168.1.10"
        self.community = "public"
        self.port = 161
        self.interval = 15
        self.enabled = False
        self.remotes: list[dict] = []
        self.error: str | None = None
        self.updated_at = ""
        self.polling = False
        self._on_update = on_update
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._load()

    def _load(self) -> None:
        try:
            saved = json.loads(CONFIG_PATH.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(saved, dict):
            return
        host = str(saved.get("host") or "").strip()
        community = str(saved.get("community") or "").strip()
        if _HOST.fullmatch(host):
            self.host = host
        if community and len(community) <= 256:
            self.community = community
        try:
            port = int(saved.get("port") or self.port)
            interval = int(saved.get("interval") or self.interval)
        except (TypeError, ValueError):
            return
        if 1 <= port <= 65535:
            self.port = port
        if 5 <= interval <= 300:
            self.interval = interval
        self.enabled = bool(saved.get("enabled"))

    def _save(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(
            json.dumps(
                {
                    "host": self.host,
                    "community": self.community,
                    "port": self.port,
                    "interval": self.interval,
                    "enabled": self.enabled,
                },
                indent=2,
            )
        )

    def snapshot(self) -> dict:
        return {
            "host": self.host,
            "community": self.community,
            "port": self.port,
            "interval": self.interval,
            "enabled": self.enabled,
            "polling": self.polling,
            "error": self.error,
            "updatedAt": self.updated_at,
            "count": len(self.remotes),
            "remotes": self.remotes,
            "table": ENTRY,
        }

    def configure(
        self,
        *,
        host: str,
        community: str,
        port: int,
        interval: int,
        enabled: bool,
    ) -> None:
        host = host.strip()
        community = community.strip()
        if not _HOST.fullmatch(host):
            raise ValueError("Master address must be a hostname or IPv4 address.")
        if not community or len(community) > 256:
            raise ValueError("Community must be 1 to 256 characters.")
        if not 1 <= int(port) <= 65535:
            raise ValueError("SNMP port must be from 1 to 65535.")
        if not 5 <= int(interval) <= 300:
            raise ValueError("Poll interval must be from 5 to 300 seconds.")
        self.host = host
        self.community = community
        self.port = int(port)
        self.interval = int(interval)
        self.enabled = bool(enabled)
        self._save()
        self._ensure_loop()

    def _ensure_loop(self) -> None:
        if self.enabled:
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(self._loop())
            return
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        while self.enabled:
            await self.poll()
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                return

    async def poll(self) -> list[dict]:
        async with self._lock:
            self.polling = True
            try:
                binds = await _walk(self.host, self.port, self.community)
                self.remotes = rows_from_binds(binds)
                self.error = None
                self.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            except Exception as exc:
                self.error = str(exc)[:300]
                log.warning("master poll failed: %s", self.error)
            finally:
                self.polling = False
        await self._on_update(self.snapshot())
        return self.remotes


async def _walk(host: str, port: int, community: str) -> list[tuple[str, object]]:
    engine = SnmpEngine()
    target = UdpTransportTarget((host, port), timeout=2, retries=1)
    auth = CommunityData(community, mpModel=1)
    context = ContextData()
    request = ObjectType(ObjectIdentity(ENTRY))
    try:
        return await _collect(
            bulkWalkCmd(engine, auth, target, context, 0, 25, request, lexicographicMode=False)
        )
    except Exception:
        log.info("bulk walk failed, falling back to get-next")
        return await _collect(
            walkCmd(engine, auth, target, context, request, lexicographicMode=False)
        )


async def _collect(stream) -> list[tuple[str, object]]:
    found: list[tuple[str, object]] = []
    async for error_indication, error_status, _error_index, var_binds in stream:
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(str(error_status))
        for var_bind in var_binds:
            name = ".".join(str(int(part)) for part in var_bind[0])
            found.append((name, var_bind[1]))
            if len(found) > _MAX_REMOTES * 30:
                return found
    return found
