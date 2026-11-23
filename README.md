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
- OPC UA: `opc.tcp://127.0.0.1:4840/trapsnmp/`
- Namespace: `urn:trapsnmp:snmp`

The default SNMPv3 user is `trapsnmp`, authPriv, SHA passphrase `trapsnmp-auth`, AES passphrase `trapsnmp-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/trapsnmp` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. The trap-tag driver also latches `TRAP_V1` / `TRAP_V2C` Booleans, fills each tag's virtual table, and queues the message at `EVENTS_001`. Write false to a Boolean to arm the next change. An optional upstream client can also write the trap JSON to another OPC UA node.

The built-in SNMP agent answers Get, GetNext, GetBulk, and Set on UDP 1161, and can forward the latest trap to configured destinations.

## GE Orbit radios

The Radios page polls a GE Orbit LN master (`mIfLnStatusConnRemTable`) and writes each connected radio into `Remote1` through `Remote255`. Every remote has the short tags (`remote_mac`, `remote_ip`, `rssi`, `down`, `if_index`) plus one tag per column of `mIfLnStatusConnRemEntry` in MDS-IF-LN-MIB. The master IP, community, port, and poll interval are set on the Config page.

The Send page can simulate those columns for Remote1 through Remote255 on one RSSI sine wave, with a random offset per remote. The wave period is 30 seconds and the step is 10 seconds. It stays stopped until you start it.

## OPC UA security

The server still accepts an anonymous session on security None. It also offers Basic256Sha256, Aes128-SHA256-RSA-OAEP, and Aes256-SHA256-RSA-PSS, in Sign and SignAndEncrypt. The application certificate is created on first start under `data/pki/own/`. A client certificate that is not trusted is stored in `data/pki/rejected` and can be trusted from the Publish page.

A username token is offered as well. On the open endpoint the password is encrypted with Basic256Sha256 and the server certificate. The first user is `trapsnmp` / `trapsnmp`.

## Settings

Communities, SNMPv3 users, the GE master, the agent, tag filters, upstream OPC UA, OPC UA users, and the last remote values are stored in `data/trapsnmp.ini` and loaded on the next start. The file is mode `0600`. Set `TRAPSNMP_DATA` to choose that folder. Otherwise an existing `/workspace/data` is used, then `./data`. The private key is not written into that file.

The console asks for the password in `[console]` of `data/trapsnmp.ini`. Until you change that line, the password is `P@ssw0rd`.

The RSSI sine stays stopped at startup. Start it from the Send page. Each step is 10 seconds.
