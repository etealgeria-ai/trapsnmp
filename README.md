# Trapwell

Python gateway that receives SNMP traps and informs, then publishes each one as OPC UA variables and a `SnmpTrapEvent`.

Supports SNMPv1, SNMPv2c, and SNMPv3 (`noAuthNoPriv`, `authNoPriv`, `authPriv`). SNMPv3 auth can be MD5, SHA, or SHA-256. Privacy can be DES or AES-128. A known user is localized to whatever engine ID the sender uses.

## Run

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m trapwell
```

- Console: `http://127.0.0.1:8080/`
- SNMP traps: UDP 162, or 1162 if 162 is unavailable
- OPC UA: `opc.tcp://127.0.0.1:4840/trapwell/` (anonymous, security None)
- Namespace: `urn:trapwell:snmp`

The default SNMPv3 user is `trapwell`, authPriv, SHA passphrase `trapwell-auth`, AES passphrase `trapwell-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/Trapwell` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. An optional upstream client can also write the trap JSON to another OPC UA node.
