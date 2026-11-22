"""Trap names, OID labels, and bench presets."""

from __future__ import annotations

OID_RE = r"^[0-2](?:\.\d+){1,127}$"

# Longest-prefix wins. Keys are numeric OIDs without a leading dot.
OID_NAMES: dict[str, str] = {
    "1.3.6.1.2.1.1.3.0": "sysUpTime.0",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.5.0": "sysName.0",
    "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID.0",
    "1.3.6.1.6.3.1.1.4.3.0": "snmpTrapEnterprise.0",
    "1.3.6.1.6.3.18.1.3.0": "snmpTrapAddress.0",
    "1.3.6.1.6.3.18.1.4.0": "snmpTrapCommunity.0",
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.4.1.99999.1.1": "envTemperatureHigh",
    "1.3.6.1.4.1.99999.1.1.1.0": "envTempCelsius",
    "1.3.6.1.4.1.99999.1.1.2.0": "envSensorName",
    "1.3.6.1.4.1.99999.1.2": "upsOnBattery",
    "1.3.6.1.4.1.99999.1.2.1.0": "upsChargePercent",
    "1.3.6.1.4.1.99999.1.2.2.0": "upsMinutesRemain",
    "1.3.6.1.4.1.99999.1.3": "diskAlmostFull",
    "1.3.6.1.4.1.99999.1.3.1.0": "dskPath",
    "1.3.6.1.4.1.99999.1.3.2.0": "dskPercent",
}

# level, OPC UA severity (1–1000), display name
TRAP_META: dict[str, tuple[str, int, str]] = {
    "1.3.6.1.6.3.1.1.5.1": ("warning", 500, "coldStart"),
    "1.3.6.1.6.3.1.1.5.2": ("warning", 400, "warmStart"),
    "1.3.6.1.6.3.1.1.5.3": ("critical", 800, "linkDown"),
    "1.3.6.1.6.3.1.1.5.4": ("info", 200, "linkUp"),
    "1.3.6.1.6.3.1.1.5.5": ("critical", 900, "authenticationFailure"),
    "1.3.6.1.6.3.1.1.5.6": ("warning", 550, "egpNeighborLoss"),
    "1.3.6.1.4.1.99999.1.1": ("critical", 850, "envTemperatureHigh"),
    "1.3.6.1.4.1.99999.1.2": ("critical", 880, "upsOnBattery"),
    "1.3.6.1.4.1.99999.1.3": ("warning", 600, "diskAlmostFull"),
}

IF_OPER = {
    "1": "up (1)",
    "2": "down (2)",
    "3": "testing (3)",
    "4": "unknown (4)",
    "5": "dormant (5)",
    "6": "notPresent (6)",
    "7": "lowerLayerDown (7)",
}
IF_ADMIN = {"1": "up (1)", "2": "down (2)", "3": "testing (3)"}

PRESETS: list[dict] = [
    {
        "id": "linkDown",
        "label": "Link down",
        "detail": "Gi0/4 left the operational state",
        "version": "2c",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "varbinds": [
            ("1.3.6.1.2.1.2.2.1.1.4", "integer", "4"),
            ("1.3.6.1.2.1.2.2.1.2.4", "string", "Gi0/4"),
            ("1.3.6.1.2.1.2.2.1.7.4", "integer", "1"),
            ("1.3.6.1.2.1.2.2.1.8.4", "integer", "2"),
        ],
    },
    {
        "id": "linkUp",
        "label": "Link up",
        "detail": "Gi0/4 is operational again",
        "version": "2c",
        "trap_oid": "1.3.6.1.6.3.1.1.5.4",
        "varbinds": [
            ("1.3.6.1.2.1.2.2.1.1.4", "integer", "4"),
            ("1.3.6.1.2.1.2.2.1.2.4", "string", "Gi0/4"),
            ("1.3.6.1.2.1.2.2.1.8.4", "integer", "1"),
        ],
    },
    {
        "id": "coldStart",
        "label": "Cold start",
        "detail": "Agent rebooted and reinitialized",
        "version": "2c",
        "trap_oid": "1.3.6.1.6.3.1.1.5.1",
        "varbinds": [
            ("1.3.6.1.2.1.1.5.0", "string", "edge-sw-04"),
        ],
    },
    {
        "id": "authFail",
        "label": "Auth failure",
        "detail": "Community rejected by the agent",
        "version": "2c",
        "trap_oid": "1.3.6.1.6.3.1.1.5.5",
        "varbinds": [],
    },
    {
        "id": "tempHigh",
        "label": "Inlet overtemp",
        "detail": "Rack A sensor at 82°C",
        "version": "2c",
        "trap_oid": "1.3.6.1.4.1.99999.1.1",
        "varbinds": [
            ("1.3.6.1.4.1.99999.1.1.2.0", "string", "Rack A inlet"),
            ("1.3.6.1.4.1.99999.1.1.1.0", "gauge", "82"),
        ],
    },
    {
        "id": "upsBattery",
        "label": "UPS on battery",
        "detail": "18% charge, about 6 minutes left",
        "version": "2c",
        "trap_oid": "1.3.6.1.4.1.99999.1.2",
        "varbinds": [
            ("1.3.6.1.4.1.99999.1.2.1.0", "gauge", "18"),
            ("1.3.6.1.4.1.99999.1.2.2.0", "integer", "6"),
        ],
    },
    {
        "id": "diskFull",
        "label": "Disk almost full",
        "detail": "/var at 94%",
        "version": "2c",
        "trap_oid": "1.3.6.1.4.1.99999.1.3",
        "varbinds": [
            ("1.3.6.1.4.1.99999.1.3.1.0", "string", "/var"),
            ("1.3.6.1.4.1.99999.1.3.2.0", "integer", "94"),
        ],
    },
    {
        "id": "v1LinkDown",
        "label": "SNMPv1 link down",
        "detail": "Same event, classic v1 trap",
        "version": "1",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "varbinds": [
            ("1.3.6.1.2.1.2.2.1.2.4", "string", "Gi0/4"),
            ("1.3.6.1.2.1.2.2.1.8.4", "integer", "2"),
        ],
    },
    {
        "id": "v3LinkDown",
        "label": "SNMPv3 link down",
        "detail": "authPriv SHA + AES as user trapwell",
        "version": "3",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "varbinds": [
            ("1.3.6.1.2.1.2.2.1.1.4", "integer", "4"),
            ("1.3.6.1.2.1.2.2.1.2.4", "string", "Gi0/4"),
            ("1.3.6.1.2.1.2.2.1.8.4", "integer", "2"),
        ],
    },
]

PRESET_BY_ID = {item["id"]: item for item in PRESETS}


def oid_name(oid: str) -> str:
    if oid in OID_NAMES:
        return OID_NAMES[oid]
    best = ""
    best_name = ""
    for prefix, name in OID_NAMES.items():
        if oid == prefix or oid.startswith(prefix + "."):
            if len(prefix) > len(best):
                best = prefix
                best_name = name
    if not best_name:
        return oid
    if oid == best:
        return best_name
    return best_name + oid[len(best) :]


def classify_trap(oid: str) -> tuple[str, int, str]:
    meta = TRAP_META.get(oid)
    if meta:
        return meta
    tail = oid.rsplit(".", 1)[-1] if oid else "trap"
    return ("info", 100, f"trap-{tail}")


def display_value(oid: str, syntax: str, value: str) -> str:
    if oid.startswith("1.3.6.1.2.1.2.2.1.8"):
        return IF_OPER.get(value, value)
    if oid.startswith("1.3.6.1.2.1.2.2.1.7"):
        return IF_ADMIN.get(value, value)
    if syntax == "TimeTicks" and value.isdigit():
        ticks = int(value)
        seconds, hundredths = divmod(ticks, 100)
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours:d}:{minutes:02d}:{seconds:02d}.{hundredths:02d}"
    return value
