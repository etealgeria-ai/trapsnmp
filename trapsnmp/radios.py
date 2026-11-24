"""Poll a GE MDS Orbit LN master for connected remote radios.

MDS-IF-LN-MIB defines mIfLnStatusConnRemEntry at
1.3.6.1.4.1.4130.10.2.5.1.2.2.1 (mdsInterfaces.5.1.2.2.1).
The index is ifIndex plus mIfLnStatusConnRemAddress. Column 6 is
mIfLnStatusConnRemRssi and column 23 is mIfLnStatusConnRemStatsDwnRssi.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone

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


def _master_address(value: str, *, required: bool) -> str:
    text = value.strip()
    if not text:
        if required:
            raise ValueError("GE Master Station 1 address is required.")
        return ""
    if not _HOST.fullmatch(text):
        raise ValueError("Each master address must be a hostname or IPv4 address.")
    return text
_MAX_REMOTES = 255

# Names and numbers are from MDS-IF-LN-MIB (May 16, 2018).
LINK_STATUS = {
    0: "initializing",
    1: "scanning",
    2: "negotiating",
    3: "authenticating",
    4: "associated",
    5: "disassociated",
}
MODULATION = {
    0: "unknown",
    4: "qpsk",
    16: "qam16",
    32: "qam32",
    64: "qam64",
    65: "fsk9600",
    66: "fsk9600m",
    67: "fsk19200",
    68: "fsk19200m",
    69: "fsk3200",
    70: "fsk19200e",
    71: "fsk19200n",
    72: "fsk38400n",
    73: "fsk38400e",
}

# column, row key, OPC UA tag, decoder
CONN_REM_COLUMNS = (
    ("1", "address", "mIfLnStatusConnRemAddress", "mac"),
    ("2", "ip", "mIfLnStatusConnRemIpAddress", "ip"),
    ("3", "ttl", "mIfLnStatusConnRemTimeToLive", "uint"),
    ("4", "link", "mIfLnStatusConnRemLinkStatus", "link"),
    ("5", "nicId", "mIfLnStatusConnRemNicId", "uint"),
    ("6", "rssi", "mIfLnStatusConnRemRssi", "int"),
    ("7", "evm", "mIfLnStatusConnRemEvm", "uint"),
    ("8", "mod", "mIfLnStatusConnRemMod", "mod"),
    ("9", "txPackets", "mIfLnStatusConnRemStatsTxPackets", "uint"),
    ("10", "txBytes", "mIfLnStatusConnRemStatsTxBytes", "uint"),
    ("11", "rxPackets", "mIfLnStatusConnRemStatsRxPackets", "uint"),
    ("12", "rxBytes", "mIfLnStatusConnRemStatsRxBytes", "uint"),
    ("13", "txError", "mIfLnStatusConnRemStatsTxError", "uint"),
    ("14", "rxError", "mIfLnStatusConnRemStatsRxError", "uint"),
    ("15", "txDrop", "mIfLnStatusConnRemStatsTxDrop", "uint"),
    ("16", "rxDrop", "mIfLnStatusConnRemStatsRxDrop", "uint"),
    ("17", "gateway", "mIfLnStatusConnRemStatsGateway", "mac"),
    ("18", "allIp", "mIfLnStatusConnRemStatsAllIp", "text"),
    ("19", "name", "mIfLnStatusConnRemStatsName", "text"),
    ("20", "alarmed", "mIfLnStatusConnRemStatsAlarmed", "bool"),
    ("21", "version", "mIfLnStatusConnRemStatsVersion", "text"),
    ("22", "temp", "mIfLnStatusConnRemStatsTemp", "int"),
    ("23", "downRssi", "mIfLnStatusConnRemStatsDwnRssi", "int"),
    ("24", "downEvm", "mIfLnStatusConnRemStatsDwnEvm", "uint"),
    ("25", "downMod", "mIfLnStatusConnRemStatsDwnMod", "mod"),
)

_OPC_KIND = {
    "mac": "string",
    "ip": "string",
    "text": "string",
    "link": "string",
    "mod": "string",
    "int": "int",
    "uint": "uint",
    "bool": "bool",
}

# Short names the console already shows, then one tag per MIB column.
OPC_TAGS = (
    ("remote_mac", "string"),
    ("remote_ip", "string"),
    ("rssi", "int"),
    ("down", "int"),
    ("if_index", "uint"),
    ("master", "string"),
    ("oid", "string"),
) + tuple((name, _OPC_KIND[kind]) for _column, _key, name, kind in CONN_REM_COLUMNS)

SLOT_KEYS = (
    "oid",
    "remote_mac",
    "remote_ip",
    "rssi",
    "down",
    "if_index",
    "master",
    "link",
    "ttl",
    "nicId",
    "evm",
    "mod",
    "name",
    "temp",
    "alarmed",
    "version",
    "gateway",
    "txPackets",
    "txBytes",
    "rxPackets",
    "rxBytes",
    "txError",
    "rxError",
    "txDrop",
    "rxDrop",
    "downEvm",
    "downMod",
    "allIp",
)


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
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    text = str(value).strip()
    if text.startswith("-") or text.isdigit():
        try:
            return int(text)
        except ValueError:
            return None
    return None


def _octets(value) -> bytes:
    """Raw bytes of an OCTET STRING. Never calls bytes() on an integer,
    which would build a zero-filled buffer of that length."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    as_octets = getattr(value, "asOctets", None)
    if callable(as_octets):
        try:
            return bytes(as_octets())
        except Exception:
            return b""
    return b""


def _as_text(value) -> str:
    raw = _octets(value)
    if raw and all(32 <= byte < 127 for byte in raw):
        return raw.decode("ascii").strip()
    text = str(value).strip().strip('"')
    if text.lower().startswith("0x"):
        return ""
    return text


def _as_mac(value) -> str:
    if isinstance(value, str):
        text = value.strip().replace("-", ":")
        parts = text.split(":")
        if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", part) for part in parts):
            return ":".join(f"{int(part, 16):02X}" for part in parts)
        compact = text.lower().removeprefix("0x").replace(" ", "")
        if re.fullmatch(r"[0-9a-f]{12}", compact):
            return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()
        return ""
    raw = _octets(value)
    if len(raw) == 6:
        return ":".join(f"{byte:02X}" for byte in raw)
    return ""


def _as_ip(value) -> str:
    text = str(value).strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return text
    raw = _octets(value)
    if len(raw) == 4:
        return ".".join(str(byte) for byte in raw)
    if len(raw) == 16:
        return ":".join(f"{raw[index]:02x}{raw[index + 1]:02x}" for index in range(0, 16, 2))
    return text or ""


def _as_enum(value, names: dict[int, str]) -> str:
    number = _as_int(value)
    if number is None:
        text = _as_text(value)
        return text
    return names.get(number, str(number))


def _as_bool(value) -> bool | None:
    number = _as_int(value)
    if number == 1:
        return True
    if number == 2 or number == 0:
        return False
    text = str(value).strip().lower()
    if text in ("true", "1"):
        return True
    if text in ("false", "2", "0"):
        return False
    return None


def _decode(kind: str, value):
    if kind == "mac":
        return _as_mac(value) or None
    if kind == "ip":
        return _as_ip(value) or None
    if kind == "int":
        return _as_int(value)
    if kind == "uint":
        number = _as_int(value)
        if number is None or number < 0:
            return None
        return number
    if kind == "text":
        return _as_text(value) or None
    if kind == "link":
        return _as_enum(value, LINK_STATUS) or None
    if kind == "mod":
        return _as_enum(value, MODULATION) or None
    if kind == "bool":
        return _as_bool(value)
    return None


def _blank_row(if_index: int, mac: str, index: str) -> dict:
    row = {key: None for _column, key, _name, _kind in CONN_REM_COLUMNS}
    row.update(
        {
            "ifIndex": if_index,
            "mac": mac,
            "key": mac.replace(":", ""),
            "address": mac,
            "oid": f"{ENTRY}.6.{index}",
        }
    )
    return row


def rows_from_binds(binds: list[tuple[str, object]]) -> list[dict]:
    grouped: dict[str, dict] = {}
    by_column = {column: (key, kind) for column, key, _name, kind in CONN_REM_COLUMNS}
    for oid, value in binds:
        split = split_instance(oid)
        if split is None:
            continue
        column, index = split
        parsed = parse_index(index)
        if parsed is None:
            continue
        if_index, mac = parsed
        row = grouped.setdefault(index, _blank_row(if_index, mac, index))
        spec = by_column.get(column)
        if spec is None:
            continue
        key, kind = spec
        try:
            row[key] = _decode(kind, value)
        except Exception:
            log.debug("could not decode %s", oid, exc_info=True)
            row[key] = None
    rows = list(grouped.values())
    rows.sort(key=lambda item: (item["ifIndex"], item["mac"]))
    return rows[:_MAX_REMOTES]


def _blank_opc(kind: str):
    if kind == "bool":
        return False
    if kind in ("int", "uint"):
        return 0
    return ""


def _opc_value(value, kind: str):
    if value is None or value == "" or value == "—":
        return _blank_opc(kind)
    if kind == "bool":
        return bool(value)
    if kind in ("int", "uint"):
        return int(value)
    return str(value)


def remote_opc_values(row: dict | None) -> list[tuple[str, object, str]]:
    if row is None:
        return [(name, _blank_opc(kind), kind) for name, kind in OPC_TAGS]
    ip = row.get("ip")
    source = {
        "remote_mac": row.get("mac") or "",
        "remote_ip": "" if ip in (None, "—") else ip,
        "rssi": row.get("rssi"),
        "down": row.get("downRssi"),
        "if_index": row.get("ifIndex") or 0,
        "master": row.get("master") or "",
        "oid": row.get("oid") or "",
    }
    for _column, key, name, _kind in CONN_REM_COLUMNS:
        source[name] = row.get(key)
    return [(name, _opc_value(source.get(name), kind), kind) for name, kind in OPC_TAGS]


def slot_fields(row: dict | None) -> dict:
    if row is None:
        return {key: None for key in SLOT_KEYS}
    ip = row.get("ip")
    values = {key: row.get(key) for key in SLOT_KEYS}
    values["remote_mac"] = row.get("mac") or None
    values["remote_ip"] = None if ip in (None, "", "—") else ip
    values["down"] = row.get("downRssi")
    values["if_index"] = row.get("ifIndex")
    values["master"] = row.get("master")
    return values


class OrbitMaster:
    def __init__(self, on_update) -> None:
        self.hosts = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]
        self.community = "public"
        self.port = 161
        self.interval = 15
        self.active = [False, False, False]
        self.stations: list[list[dict]] = [[], [], []]
        self.error: str | None = None
        self.updated_at = ""
        self.polling = False
        self._on_update = on_update
        self.on_save = None
        self._task: asyncio.Task | None = None
        self._snmp = None
        self._lock = asyncio.Lock()

    @property
    def host(self) -> str:
        for item in self.hosts:
            if item:
                return item
        return ""

    @host.setter
    def host(self, value: str) -> None:
        self.hosts[0] = str(value or "").strip()

    def _save(self) -> None:
        if self.on_save:
            self.on_save()

    def station_name(self, source: str) -> str:
        source = (source or "").strip()
        labels = ("GE Master Station 1", "GE Master Station 2", "GE Master Station 3")
        for label, host in zip(labels, self.hosts):
            if host and host == source:
                return label
        return ""

    def station_index(self, source: str) -> int | None:
        source = (source or "").strip()
        for index, host in enumerate(self.hosts):
            if host and host == source:
                return index
        return None

    def apply_trap(self, source: str, binds: list[tuple[str, object]]) -> tuple[int, list[tuple[int, dict]]] | None:
        """Update one master from a trap. The source IP selects the master."""
        index = self.station_index(source)
        if index is None or not self.active[index]:
            return None
        incoming = rows_from_binds([(str(oid).lstrip("."), value) for oid, value in binds])
        if not incoming:
            return None
        current = list(self.stations[index])
        positions = {str(row.get("mac") or ""): slot for slot, row in enumerate(current) if row.get("mac")}
        changed: list[tuple[int, dict]] = []
        for row in incoming:
            row["master"] = self.hosts[index]
            row["source"] = source
            mac = str(row.get("mac") or "")
            if mac and mac in positions:
                slot = positions[mac]
                existing = current[slot]
                for key, value in row.items():
                    if value not in (None, ""):
                        existing[key] = value
                changed.append((slot + 1, existing))
            elif len(current) < _MAX_REMOTES:
                current.append(row)
                changed.append((len(current), row))
        if not changed:
            return None
        self.stations[index] = current
        self.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.error = None
        return index + 1, changed

    @property
    def enabled(self) -> bool:
        return any(self.active)

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self.active = [bool(value), bool(value), bool(value)]

    @property
    def remotes(self) -> list[dict]:
        return [row for group in self.stations for row in group]

    @remotes.setter
    def remotes(self, rows: list[dict]) -> None:
        self.stations[0] = list(rows)[:_MAX_REMOTES]

    def snapshot(self) -> dict:
        filled = [item for item in self.hosts if item]
        return {
            "host": ", ".join(filled),
            "hosts": list(self.hosts),
            "community": self.community,
            "port": self.port,
            "interval": self.interval,
            "enabled": self.enabled,
            "active": list(self.active),
            "polling": self.polling,
            "error": self.error,
            "updatedAt": self.updated_at,
            "count": sum(len(group) for group in self.stations),
            "masterCounts": [len(group) for group in self.stations],
            "stations": self.stations,
            "remotes": self.remotes,
            "table": ENTRY,
        }

    def configure(
        self,
        *,
        host: str,
        host2: str = "",
        host3: str = "",
        community: str,
        port: int,
        interval: int,
        enabled: bool,
        active: list[bool] | None = None,
    ) -> None:
        hosts = [
            _master_address(host, required=True),
            _master_address(host2, required=False),
            _master_address(host3, required=False),
        ]
        filled = [item for item in hosts if item]
        if len(filled) != len(set(filled)):
            raise ValueError("GE Master Station addresses must be different.")
        community = community.strip()
        if not community or len(community) > 256:
            raise ValueError("Community must be 1 to 256 characters.")
        if not 1 <= int(port) <= 65535:
            raise ValueError("SNMP port must be from 1 to 65535.")
        if not 5 <= int(interval) <= 300:
            raise ValueError("Poll interval must be from 5 to 300 seconds.")
        self.hosts = hosts
        self.community = community
        self.port = int(port)
        self.interval = int(interval)
        if active is None:
            self.enabled = bool(enabled)
        else:
            flags = [bool(item) for item in list(active)[:3]]
            while len(flags) < 3:
                flags.append(False)
            self.active = flags
        self._save()
        self._ensure_loop()

    def set_active(self, index: int, enabled: bool) -> None:
        if not 0 <= int(index) <= 2:
            raise ValueError("Choose GE Master Station 1, 2, or 3.")
        index = int(index)
        if enabled and not self.hosts[index]:
            raise ValueError("Enter an address before activating this station.")
        self.active[index] = bool(enabled)
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
            try:
                await self.poll()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("radio poll cycle failed")
            try:
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                return

    async def poll(self) -> list[dict]:
        async with self._lock:
            self.polling = True
            try:
                stations: list[list[dict]] = [[], [], []]
                errors: list[str] = []
                for index, host in enumerate(self.hosts):
                    if not host or not self.active[index]:
                        continue
                    try:
                        binds = await _walk(self._engine(), host, self.port, self.community)
                    except Exception as exc:
                        errors.append(f"{host}: {exc}")
                        stations[index] = list(self.stations[index])
                        continue
                    rows: list[dict] = []
                    seen: set[str] = set()
                    for row in rows_from_binds(binds):
                        row["master"] = host
                        mac = str(row.get("mac") or "")
                        if mac and mac in seen:
                            continue
                        if mac:
                            seen.add(mac)
                        rows.append(row)
                        if len(rows) >= _MAX_REMOTES:
                            break
                    stations[index] = rows
                if any(stations) or not errors:
                    self.stations = stations
                error = "; ".join(errors)[:300]
                if error != (self.error or ""):
                    if error:
                        log.warning("master poll failed: %s", error)
                    elif self.error:
                        log.info("master poll recovered")
                self.error = error or None
                self.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            except Exception as exc:
                error = str(exc)[:300]
                if error != self.error:
                    # Logged when the failure starts or changes, not every poll.
                    log.warning("master poll failed: %s", error)
                self.error = error
            finally:
                self.polling = False
        await self._on_update(self.snapshot())
        return self.remotes

    def _engine(self):
        if self._snmp is None:
            self._snmp = SnmpEngine()
        return self._snmp


async def _walk(engine, host: str, port: int, community: str) -> list[tuple[str, object]]:
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
