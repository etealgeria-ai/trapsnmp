"""OPC UA server for trap state, plus an optional client that forwards each trap."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from asyncua import Client, Server, ua

log = logging.getLogger("trapsnmp.opcua")

NS_URI = "urn:trapsnmp:snmp"
SLOT_COUNT = 8

LATEST_FIELDS = (
    ("Source", ua.VariantType.String, ""),
    ("SourcePort", ua.VariantType.UInt16, 0),
    ("Community", ua.VariantType.String, ""),
    ("User", ua.VariantType.String, ""),
    ("SecurityLevel", ua.VariantType.String, ""),
    ("Version", ua.VariantType.String, ""),
    ("Kind", ua.VariantType.String, ""),
    ("TrapOid", ua.VariantType.String, ""),
    ("TrapName", ua.VariantType.String, ""),
    ("Severity", ua.VariantType.String, ""),
    ("SeverityCode", ua.VariantType.UInt16, 0),
    ("SysUpTime", ua.VariantType.UInt32, 0),
    ("Message", ua.VariantType.String, ""),
    ("Varbinds", ua.VariantType.String, ""),
)


def _iso(value) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="seconds")
    return "" if value is None else str(value)


class OpcuaBridge:
    def __init__(self) -> None:
        self.ready = False
        self.error: str | None = None
        self.endpoint = "opc.tcp://127.0.0.1:4840/trapsnmp/"
        self.namespace_index = 0
        self.event_count = 0
        self.nodes: dict = {}
        self.node_ids: dict[str, str] = {}
        self._server: Server | None = None
        self._events = None
        self._reader: Client | None = None
        self._forwarder: Client | None = None
        self._forward_url = ""
        self._read_lock = asyncio.Lock()
        self.upstream = {
            "enabled": False,
            "endpoint": "",
            "nodeId": "",
            "status": "Not forwarding",
            "forwarded": 0,
            "failed": 0,
        }

    async def start(self) -> None:
        server = Server()
        await server.init()
        await server.set_application_uri("urn:trapsnmp:gateway")
        server.product_uri = "urn:trapsnmp:snmp-opcua"
        server.manufacturer_name = "trapsnmp"
        server.set_server_name("trapsnmp SNMP Gateway")
        server.set_endpoint(self.endpoint)
        server.socket_address = ("0.0.0.0", 4840)
        server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
        try:
            idx = await server.register_namespace(NS_URI)
            objects = server.nodes.objects
            root = await objects.add_object(ua.NodeId("trapsnmp", idx), "trapsnmp")
            self.node_ids["trapsnmp"] = f"ns={idx};s=trapsnmp"
            gateway = await root.add_object(ua.NodeId("Gateway", idx), "Gateway")
            latest = await root.add_object(ua.NodeId("Latest", idx), "Latest")
            recent = await root.add_object(ua.NodeId("Recent", idx), "Recent")
            upstream = await root.add_object(ua.NodeId("Upstream", idx), "Upstream")

            async def add_var(parent, node_key: str, browse: str, value, variant):
                node = await parent.add_variable(
                    ua.NodeId(node_key, idx), browse, value, varianttype=variant
                )
                self.nodes[node_key] = node
                self.node_ids[node_key] = f"ns={idx};s={node_key}"

            await add_var(gateway, "Gateway.Listening", "Listening", False, ua.VariantType.Boolean)
            await add_var(gateway, "Gateway.UdpPort", "UdpPort", 0, ua.VariantType.UInt16)
            await add_var(gateway, "Gateway.TrapCount", "TrapCount", 0, ua.VariantType.UInt64)
            await add_var(gateway, "Gateway.InformCount", "InformCount", 0, ua.VariantType.UInt64)
            await add_var(gateway, "Gateway.LastError", "LastError", "", ua.VariantType.String)
            received = datetime(1970, 1, 1, tzinfo=timezone.utc)
            await add_var(latest, "Latest.ReceivedAt", "ReceivedAt", received, ua.VariantType.DateTime)
            for name, variant, initial in LATEST_FIELDS:
                await add_var(latest, f"Latest.{name}", name, initial, variant)
            for slot in range(1, SLOT_COUNT + 1):
                folder = await recent.add_object(ua.NodeId(f"Recent.{slot}", idx), f"Slot{slot}")
                for name in ("TrapOid", "TrapName", "Source", "Severity", "ReceivedAt"):
                    await add_var(
                        folder,
                        f"Recent.{slot}.{name}",
                        name,
                        "",
                        ua.VariantType.String,
                    )
            await add_var(upstream, "Upstream.Inbox", "Inbox", "", ua.VariantType.String)
            await self.nodes["Upstream.Inbox"].set_writable(True)
            await add_var(upstream, "Upstream.Status", "Status", "Not forwarding", ua.VariantType.String)
            await add_var(upstream, "Upstream.Forwarded", "Forwarded", 0, ua.VariantType.UInt64)

            event_type = await server.create_custom_event_type(
                idx,
                "SnmpTrapEvent",
                ua.ObjectIds.BaseEventType,
                [
                    ("TrapOid", ua.VariantType.String),
                    ("SourceAddress", ua.VariantType.String),
                    ("Community", ua.VariantType.String),
                    ("SeverityName", ua.VariantType.String),
                    ("Varbinds", ua.VariantType.String),
                ],
            )
            self._events = await server.get_event_generator(event_type, root)
            await server.start()
        except Exception as exc:
            self.error = str(exc)
            self.ready = False
            log.exception("OPC UA server failed")
            try:
                await server.stop()
            except Exception:
                pass
            return
        self._server = server
        self.namespace_index = idx
        self.ready = True
        self.error = None
        log.info("OPC UA server at %s (ns=%s)", self.endpoint, idx)
        try:
            await self._connect_reader()
        except Exception as exc:
            log.warning("OPC UA readback client not connected yet: %s", exc)

    async def set_listener(self, listening: bool, port: int) -> None:
        if not self.ready:
            return
        await self._write("Gateway.Listening", listening, ua.VariantType.Boolean)
        await self._write("Gateway.UdpPort", int(port or 0), ua.VariantType.UInt16)

    async def publish(self, trap: dict, history: list[dict], counts: dict) -> dict:
        result = {"event": False, "written": 0, "upstream": "skipped", "error": None}
        if not self.ready:
            result["error"] = self.error or "OPC UA server is not running"
            return result
        try:
            pairs = [
                ("Latest.Source", trap["source"], ua.VariantType.String),
                ("Latest.SourcePort", int(trap["sourcePort"]), ua.VariantType.UInt16),
                ("Latest.Community", trap["community"], ua.VariantType.String),
                ("Latest.User", trap.get("user", ""), ua.VariantType.String),
                ("Latest.SecurityLevel", trap.get("securityLevel", ""), ua.VariantType.String),
                ("Latest.Version", trap["version"], ua.VariantType.String),
                ("Latest.Kind", trap["kind"], ua.VariantType.String),
                ("Latest.TrapOid", trap["trapOid"], ua.VariantType.String),
                ("Latest.TrapName", trap["trapName"], ua.VariantType.String),
                ("Latest.Severity", trap["severity"], ua.VariantType.String),
                ("Latest.SeverityCode", int(trap["severityCode"]), ua.VariantType.UInt16),
                ("Latest.SysUpTime", int(trap["sysUpTime"]), ua.VariantType.UInt32),
                ("Latest.Message", trap["message"], ua.VariantType.String),
                ("Latest.Varbinds", trap["varbindsJson"], ua.VariantType.String),
                ("Latest.ReceivedAt", trap["received"], ua.VariantType.DateTime),
                ("Gateway.TrapCount", int(counts["traps"]), ua.VariantType.UInt64),
                ("Gateway.InformCount", int(counts["informs"]), ua.VariantType.UInt64),
                ("Gateway.LastError", "", ua.VariantType.String),
            ]
            for key, value, variant in pairs:
                await self._write(key, value, variant)
            for slot in range(1, SLOT_COUNT + 1):
                item = history[slot - 1] if slot - 1 < len(history) else None
                fields = {
                    "TrapOid": item["trapOid"] if item else "",
                    "TrapName": item["trapName"] if item else "",
                    "Source": item["source"] if item else "",
                    "Severity": item["severity"] if item else "",
                    "ReceivedAt": item["receivedAt"] if item else "",
                }
                for name, value in fields.items():
                    await self._write(f"Recent.{slot}.{name}", value, ua.VariantType.String)
            result["written"] = len(pairs) + SLOT_COUNT * 5
            self._events.event.TrapOid = trap["trapOid"]
            self._events.event.SourceAddress = trap["source"]
            self._events.event.Community = trap["community"]
            self._events.event.SeverityName = trap["severity"]
            self._events.event.Varbinds = trap["varbindsJson"][:4000]
            self._events.event.Severity = int(trap["severityCode"])
            await self._events.trigger(message=trap["message"])
            self.event_count += 1
            result["event"] = True
        except Exception as exc:
            result["error"] = str(exc)
            log.exception("OPC UA publish failed")
            try:
                await self._write("Gateway.LastError", str(exc)[:400], ua.VariantType.String)
            except Exception:
                pass
            return result
        if self.upstream["enabled"]:
            result["upstream"] = await self._forward(trap)
        return result

    async def readback(self) -> dict:
        if not self.ready:
            return {"ok": False, "error": self.error or "OPC UA server is not running"}
        async with self._read_lock:
            return await self._readback()

    async def _readback(self) -> dict:
        keys = (
            "Latest.TrapOid",
            "Latest.TrapName",
            "Latest.Source",
            "Latest.Community",
            "Latest.User",
            "Latest.SecurityLevel",
            "Latest.Version",
            "Latest.Kind",
            "Latest.Severity",
            "Latest.SeverityCode",
            "Latest.Message",
            "Latest.SysUpTime",
            "Gateway.TrapCount",
            "Gateway.InformCount",
            "Gateway.UdpPort",
            "Upstream.Inbox",
            "Upstream.Status",
        )
        try:
            values = await self._read_keys(keys)
        except Exception as exc:
            await self._drop_reader()
            try:
                values = await self._read_keys(keys)
            except Exception as again:
                return {"ok": False, "error": str(again or exc)}
        received = ""
        try:
            if self._reader is not None:
                when = await self._reader.get_node(self.node_ids["Latest.ReceivedAt"]).read_value()
                received = _iso(when)
        except Exception:
            received = ""
        return {
            "ok": True,
            "error": None,
            "trapOid": values["Latest.TrapOid"],
            "trapName": values["Latest.TrapName"],
            "source": values["Latest.Source"],
            "community": values["Latest.Community"],
            "user": values["Latest.User"],
            "securityLevel": values["Latest.SecurityLevel"],
            "version": values["Latest.Version"],
            "kind": values["Latest.Kind"],
            "severity": values["Latest.Severity"],
            "severityCode": values["Latest.SeverityCode"],
            "message": values["Latest.Message"],
            "sysUpTime": values["Latest.SysUpTime"],
            "trapCount": values["Gateway.TrapCount"],
            "informCount": values["Gateway.InformCount"],
            "udpPort": values["Gateway.UdpPort"],
            "receivedAt": received,
            "inbox": values["Upstream.Inbox"],
            "upstreamStatus": values["Upstream.Status"],
        }

    def configure_upstream(self, *, enabled: bool, endpoint: str, node_id: str) -> None:
        endpoint = endpoint.strip()
        node_id = node_id.strip()
        if enabled:
            if not endpoint.startswith("opc.tcp://"):
                raise ValueError("Endpoint must start with opc.tcp://")
            if not node_id.startswith("ns="):
                raise ValueError("Node id looks like ns=2;s=Upstream.Inbox")
        self.upstream["enabled"] = enabled
        self.upstream["endpoint"] = endpoint
        self.upstream["nodeId"] = node_id
        if not enabled:
            self.upstream["status"] = "Not forwarding"
        else:
            self.upstream["status"] = "Armed"
        self._forward_url = ""

    async def _forward(self, trap: dict) -> str:
        payload = {
            "source": trap["source"],
            "sourcePort": trap["sourcePort"],
            "community": trap["community"],
            "user": trap.get("user", ""),
            "securityLevel": trap.get("securityLevel", ""),
            "version": trap["version"],
            "kind": trap["kind"],
            "trapOid": trap["trapOid"],
            "trapName": trap["trapName"],
            "severity": trap["severity"],
            "severityCode": trap["severityCode"],
            "message": trap["message"],
            "receivedAt": trap["receivedAt"],
            "varbinds": trap["varbinds"],
        }
        encoded = json.dumps(payload, separators=(",", ":"))
        try:
            client = await self._forward_client()
            node = client.get_node(self.upstream["nodeId"])
            await node.write_value(encoded, ua.VariantType.String)
        except Exception as exc:
            self.upstream["failed"] += 1
            self.upstream["status"] = str(exc)
            await self._drop_forwarder()
            log.warning("upstream write failed: %s", exc)
            return "failed"
        self.upstream["forwarded"] += 1
        self.upstream["status"] = "Last write succeeded"
        try:
            await self._write("Upstream.Status", self.upstream["status"], ua.VariantType.String)
            await self._write(
                "Upstream.Forwarded", self.upstream["forwarded"], ua.VariantType.UInt64
            )
        except Exception:
            log.exception("could not mirror upstream status")
        return "ok"

    async def _write(self, key: str, value, variant: ua.VariantType) -> None:
        await self.nodes[key].write_value(value, variant)

    async def _connect_reader(self) -> None:
        client = Client(self.endpoint)
        client.session_timeout = 600_000
        await client.connect()
        self._reader = client

    async def _drop_reader(self) -> None:
        client = self._reader
        self._reader = None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _read_keys(self, keys: tuple[str, ...]) -> dict:
        if self._reader is None:
            await self._connect_reader()
        assert self._reader is not None
        out = {}
        for key in keys:
            value = await self._reader.get_node(self.node_ids[key]).read_value()
            out[key] = _iso(value) if isinstance(value, datetime) else value
        return out

    async def _forward_client(self) -> Client:
        url = self.upstream["endpoint"]
        if self._forwarder is not None and self._forward_url == url:
            return self._forwarder
        await self._drop_forwarder()
        client = Client(url)
        client.session_timeout = 600_000
        await client.connect()
        self._forwarder = client
        self._forward_url = url
        return client

    async def _drop_forwarder(self) -> None:
        client = self._forwarder
        self._forwarder = None
        self._forward_url = ""
        if client is not None:
            try:
                await client.disconnect()
            except Exception:
                pass
