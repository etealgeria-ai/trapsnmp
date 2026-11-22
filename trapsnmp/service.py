"""Glue between the SNMP receiver, the OPC UA bridge, and the console."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from datetime import datetime, timezone

from trapsnmp import __version__
from trapsnmp.catalog import OID_RE, PRESETS, classify_trap, display_value, oid_name
from trapsnmp.opcua_out import NS_URI, OpcuaBridge
from trapsnmp.snmp_in import SnmpTrapIn

log = logging.getLogger("trapsnmp")

_OID = re.compile(OID_RE)
_MAX_BINDS = 24
_MAX_VALUE = 512


class Service:
    def __init__(self) -> None:
        self.snmp = SnmpTrapIn(self._ingest)
        self.opc = OpcuaBridge()
        self.traps: deque[dict] = deque(maxlen=50)
        self.trace: deque[str] = deque(maxlen=40)
        self.counts = {"traps": 0, "informs": 0}
        self._seq = 0
        self._inject_lock = asyncio.Lock()
        self._pending: asyncio.Future | None = None
        self._expect = ""
        self._started = False
        self.started_at = datetime.now(timezone.utc)

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        await self.snmp.start()
        await self.opc.start()
        await self.opc.set_listener(self.snmp.listening, self.snmp.port or 0)
        if self.snmp.listening:
            users = ", ".join(item["name"] for item in self.snmp.users)
            self._trace(
                "Receiver listening on UDP "
                + str(self.snmp.port)
                + ". Communities "
                + ", ".join(self.snmp.communities)
                + ". SNMPv3 users "
                + users
            )
        elif self.snmp.error:
            self._trace(f"Receiver failed: {self.snmp.error}")
        if self.opc.ready:
            self._trace(f"OPC UA server ready at {self.opc.endpoint}")
        elif self.opc.error:
            self._trace(f"OPC UA server failed: {self.opc.error}")

    async def snapshot(self) -> dict:
        readback = await self.opc.readback()
        return {
            "snmp": {
                "listening": self.snmp.listening,
                "port": self.snmp.port,
                "note": self.snmp.note,
                "communities": list(self.snmp.communities),
                "users": [dict(item) for item in self.snmp.users],
                "error": self.snmp.error,
            },
            "opcua": {
                "ready": self.opc.ready,
                "endpoint": self.opc.endpoint,
                "namespace": NS_URI,
                "namespaceIndex": self.opc.namespace_index,
                "security": "None",
                "identity": "anonymous",
                "eventType": "SnmpTrapEvent",
                "eventCount": self.opc.event_count,
                "error": self.opc.error,
                "nodes": {
                    "object": self.opc.node_ids.get("trapsnmp", "ns=2;s=trapsnmp"),
                    "trapOid": self.opc.node_ids.get("Latest.TrapOid", ""),
                    "message": self.opc.node_ids.get("Latest.Message", ""),
                    "varbinds": self.opc.node_ids.get("Latest.Varbinds", ""),
                    "count": self.opc.node_ids.get("Gateway.TrapCount", ""),
                    "inbox": self.opc.node_ids.get("Upstream.Inbox", ""),
                },
            },
            "upstream": dict(self.opc.upstream),
            "counts": {
                "traps": self.counts["traps"],
                "informs": self.counts["informs"],
                "events": self.opc.event_count,
            },
            "traps": list(self.traps),
            "readback": readback,
            "trace": list(self.trace),
            "presets": [
                {"id": item["id"], "label": item["label"], "detail": item["detail"]}
                for item in PRESETS
            ],
            "version": __version__,
            "startedAt": self.started_at.isoformat(timespec="seconds"),
        }

    async def diagnose(self) -> dict:
        started = datetime.now(timezone.utc)
        steps: list[dict] = []

        def step(name: str, ok: bool, detail: str) -> None:
            steps.append({"name": name, "ok": bool(ok), "detail": detail})

        step(
            "SNMP socket",
            self.snmp.listening,
            f"UDP {self.snmp.port}" if self.snmp.listening else (self.snmp.error or "Not listening"),
        )
        step(
            "OPC UA server",
            self.opc.ready,
            self.opc.endpoint if self.opc.ready else (self.opc.error or "Not ready"),
        )
        if self.snmp.listening and self.opc.ready:
            try:
                record = await self.inject_custom(
                    community=self.snmp.communities[0] if self.snmp.communities else "public",
                    version="2c",
                    trap_oid="1.3.6.1.6.3.1.1.5.2",
                    varbinds=[("1.3.6.1.2.1.1.5.0", "string", "trapsnmp-diag")],
                )
            except (ValueError, RuntimeError) as exc:
                step("Loopback trap", False, str(exc))
                record = None
            else:
                published = record.get("opcua") or {}
                step(
                    "Loopback trap",
                    True,
                    f"{record.get('trapName')} {record.get('version')} from {record.get('source')}",
                )
                step(
                    "OPC UA write",
                    not published.get("error") and int(published.get("written") or 0) > 0,
                    published.get("error")
                    or f"{published.get('written', 0)} nodes written",
                )
                step(
                    "Event",
                    bool(published.get("event")),
                    "SnmpTrapEvent fired" if published.get("event") else "No event",
                )
                readback = await self.opc.readback()
                matched = bool(readback.get("ok") and readback.get("trapOid") == record.get("trapOid"))
                step(
                    "Readback",
                    matched,
                    readback.get("trapName") or readback.get("error") or "Empty read",
                )
        elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        return {
            "ok": bool(steps) and all(item["ok"] for item in steps),
            "steps": steps,
            "ms": elapsed,
        }

    async def inject_preset(self, preset_id: str, community: str | None = None) -> dict:
        from trapsnmp.catalog import PRESET_BY_ID

        preset = PRESET_BY_ID.get(preset_id)
        if preset is None:
            raise ValueError("Unknown preset.")
        return await self._send_and_wait(
            community=(community or (self.snmp.communities[0] if self.snmp.communities else "public")),
            version=preset["version"],
            trap_oid=preset["trap_oid"],
            varbinds=list(preset["varbinds"]),
        )

    async def inject_custom(
        self,
        *,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None = None,
    ) -> dict:
        self._validate(community, version, trap_oid, varbinds, user)
        return await self._send_and_wait(
            community=community,
            version=version,
            trap_oid=trap_oid,
            varbinds=varbinds,
            user=user,
        )

    def allow_community(self, community: str) -> None:
        community = community.strip()
        if not community or len(community) > 64:
            raise ValueError("Community must be 1–64 characters.")
        if any(ch in community for ch in "\r\n\x00"):
            raise ValueError("Community contains a control character.")
        self.snmp.allow(community)
        self._trace(f"Community '{community}' is now accepted")

    def add_user(self, profile: dict) -> dict:
        created = self.snmp.add_user(profile)
        self._trace(f"SNMPv3 user '{created['name']}' ({created['level']}) is now accepted")
        return created

    def configure_upstream(self, *, enabled: bool, endpoint: str, node_id: str) -> None:
        self.opc.configure_upstream(enabled=enabled, endpoint=endpoint, node_id=node_id)
        if enabled:
            self._trace(f"Forwarding armed → {endpoint} {node_id}")
        else:
            self._trace("Forwarding stopped")

    async def _send_and_wait(
        self,
        *,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None = None,
    ) -> dict:
        async with self._inject_lock:
            loop = asyncio.get_running_loop()
            fut: asyncio.Future = loop.create_future()
            self._pending = fut
            self._expect = trap_oid
            try:
                await self.snmp.send(
                    community=community,
                    version=version,
                    trap_oid=trap_oid,
                    varbinds=varbinds,
                    user=user,
                )
                return await asyncio.wait_for(fut, 3.0)
            except asyncio.TimeoutError as exc:
                raise RuntimeError(
                    "The trap was sent, but the receiver did not accept it. "
                    "Check the community or the SNMPv3 user."
                ) from exc
            finally:
                if self._pending is fut:
                    self._pending = None
                    self._expect = ""

    async def _ingest(self, snap: dict, rows: list[tuple[str, str, str]]) -> None:
        trap_oid = ""
        sys_up = 0
        varbinds = []
        for oid, syntax, value in rows:
            if oid == "1.3.6.1.6.3.1.1.4.1.0":
                trap_oid = value
            elif oid == "1.3.6.1.2.1.1.3.0" and value.isdigit():
                sys_up = int(value)
            varbinds.append(
                {
                    "oid": oid,
                    "name": oid_name(oid),
                    "type": syntax,
                    "value": value,
                    "display": display_value(oid, syntax, value),
                }
            )
        level, code, name = classify_trap(trap_oid or "0.0")
        now = datetime.now(timezone.utc)
        self._seq += 1
        if snap.get("kind") == "inform":
            self.counts["informs"] += 1
        else:
            self.counts["traps"] += 1
        record = {
            "id": self._seq,
            "receivedAt": now.isoformat(timespec="seconds"),
            "received": now,
            "source": snap.get("source") or "",
            "sourcePort": int(snap.get("sourcePort") or 0),
            "community": snap.get("community") or "",
            "user": snap.get("user") or "",
            "securityLevel": snap.get("securityLevel") or "",
            "version": snap.get("version") or "",
            "kind": snap.get("kind") or "trap",
            "trapOid": trap_oid,
            "trapName": name,
            "severity": level,
            "severityCode": code,
            "sysUpTime": sys_up,
            "message": f"{name} from {snap.get('source') or 'unknown'}",
            "varbinds": varbinds,
            "varbindsJson": json.dumps(varbinds, separators=(",", ":")),
        }
        history = [record, *list(self.traps)]
        published = await self.opc.publish(record, history, self.counts)
        public = {key: value for key, value in record.items() if key != "received"}
        public["opcua"] = published
        self.traps.appendleft(public)
        upstream = published.get("upstream")
        extra = ""
        if upstream == "ok":
            extra = ", forwarded"
        elif upstream == "failed":
            extra = ", forward failed"
        if published.get("error"):
            extra += f", OPC UA error: {published['error']}"
        who = public["user"] if public["version"] == "v3" else (public["community"] or "—")
        how = f" {public['securityLevel']}" if public["version"] == "v3" else ""
        self._trace(
            f"{public['version']} {public['kind']} {public['trapName']} "
            f"from {public['source']} as {who}{how} "
            f"→ {published.get('written', 0)} node writes"
            f"{', event' if published.get('event') else ''}{extra}"
        )
        pending = self._pending
        if (
            pending is not None
            and not pending.done()
            and public["trapOid"] == self._expect
        ):
            pending.set_result(public)

    def _trace(self, line: str) -> None:
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.trace.appendleft(f"{stamp}  {line}")

    def _validate(
        self,
        community: str,
        version: str,
        trap_oid: str,
        varbinds: list[tuple[str, str, str]],
        user: str | None,
    ) -> None:
        if version not in ("1", "2c", "3"):
            raise ValueError("Version must be 1, 2c, or 3.")
        if version == "3":
            if not user or self.snmp.user_named(user) is None:
                raise ValueError("Choose a configured SNMPv3 user.")
        elif not community.strip():
            raise ValueError("Community is required.")
        if not _OID.match(trap_oid):
            raise ValueError("Trap OID must be numeric, like 1.3.6.1.6.3.1.1.5.3.")
        if len(varbinds) > _MAX_BINDS:
            raise ValueError(f"At most {_MAX_BINDS} extra varbinds.")
        for oid, kind, value in varbinds:
            if not _OID.match(oid):
                raise ValueError(f"Bad varbind OID: {oid}")
            if kind not in {
                "integer",
                "string",
                "oid",
                "timeticks",
                "gauge",
                "counter",
                "unsigned",
                "ip",
            }:
                raise ValueError(f"Unsupported type '{kind}'.")
            if len(value) > _MAX_VALUE:
                raise ValueError("Varbind value is too long.")
            if kind == "oid" and not _OID.match(value):
                raise ValueError(f"Value for {oid} is not an OID.")
