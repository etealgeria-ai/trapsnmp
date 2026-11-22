# trapsnmp

Comments in this README were made by Grok.

Python gateway that receives SNMP traps and informs, then publishes each one as OPC UA variables and a `SnmpTrapEvent`.

Supports SNMPv1, SNMPv2c, and SNMPv3 (`noAuthNoPriv`, `authNoPriv`, `authPriv`). SNMPv3 auth can be MD5, SHA, or SHA-256. Privacy can be DES or AES-128. A known user is localized to whatever engine ID the sender uses.

## Run

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m trapsnmp
```

- Console: `http://127.0.0.1:8080/`
- SNMP traps: UDP 162, or 1162 if 162 is unavailable
- OPC UA: `opc.tcp://127.0.0.1:4840/trapsnmp/` (anonymous, security None)
- Namespace: `urn:trapsnmp:snmp`

The default SNMPv3 user is `trapsnmp`, authPriv, SHA passphrase `trapsnmp-auth`, AES passphrase `trapsnmp-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/trapsnmp` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. The trap-tag driver also latches `TRAP_V1` / `TRAP_V2C` Booleans, fills each tag's virtual table, and queues the message at `EVENTS_001`. Write false to a Boolean to arm the next change. An optional upstream client can also write the trap JSON to another OPC UA node.

The built-in SNMP agent answers Get, GetNext, GetBulk, and Set on UDP 1161, and can forward the latest trap to configured destinations.

The Radios page polls a GE Orbit LN master and writes each connected radio into `Remote1` through `Remote50`. Every remote has `remote_mac`, `remote_ip`, `rssi`, `down`, and `if_index`. The master IP, community, port, and poll interval are set on the Config page and saved in `data/ge-master.json`.
