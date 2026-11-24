Software made by GrokAI

# trapsnmp

Comments in this README were made by ClaudeAI.

Python gateway that receives SNMP traps and informs, then publishes each one as OPC UA variables and a `SnmpTrapEvent`.

Supports SNMPv1, SNMPv2c, and SNMPv3 (`noAuthNoPriv`, `authNoPriv`, `authPriv`). SNMPv3 auth can be MD5, SHA, or SHA-256. Privacy can be DES or AES-128. A known user is localized to whatever engine ID the sender uses.

## Run

Requires Python 3.10+.

```bash
pip install -r requirements.txt
python -m trapsnmp
```

- Console: `http://127.0.0.1:8888/` and `https://127.0.0.1:8888/` — sign in with password `P@ssw0rd`. Yokogawa CI Server already uses TCP 8080 and 8443 (CI Portal / CI View) and TCP 443 and 80, so the console stays on 8888. Set `TRAPSNMP_PORT`, or `port` under `[console]` in `data/trapsnmp.ini`, only if 8888 is also taken. Do not use 8080, 8443, 80, or 443.
- SNMP traps: UDP 162, or 1162 if 162 is unavailable
- OPC UA: `opc.tcp://127.0.0.1:4840/trapsnmp/`
- Namespace: `urn:trapsnmp:snmp`

## Windows service

Yes. Right-click `windows\install-service.bat` and choose **Run as administrator**, or on the Config page turn on **Run as a Windows service**. That installs pywin32, registers a service named **trapsnmp**, and starts it. Windows starts the service at boot as Local System, before anyone signs in, and restarts it if the process exits. The console stays at `https://127.0.0.1:8888/`. Output is appended to `data\trapsnmp.log`. `services.msc` lists it as trapsnmp. The Config page asks for administrator approval and does nothing on Linux. Turn the same switch off to stop and remove the service.

Stop the copy you started by hand before installing, so UDP 162 and OPC UA 4840 are free. The installer also removes the startup task from `install-autorun.bat` if that task exists, so the gateway is not started twice.

`windows\remove-service.bat` (as administrator) stops and removes the service.

`windows\install-autorun.bat` is only a scheduled task. Use the service instead of that task.

The default SNMPv3 user is `trapsnmp`, authPriv, SHA passphrase `trapsnmp-auth`, AES passphrase `trapsnmp-priv`. Communities `public` and `private` are accepted. More communities and users can be added from the console.

Each trap is written under `Objects/trapsnmp` (`Latest.*`, recent slots, gateway counters) and raised as `SnmpTrapEvent`. The trap-tag driver also latches `TRAP_V1` / `TRAP_V2C` Booleans, fills each tag's virtual table, and queues the message at `EVENTS_001`. Write false to a Boolean to arm the next change. An optional upstream client can also write the trap JSON to another OPC UA node.

The built-in SNMP agent answers Get, GetNext, GetBulk, and Set on UDP 1161, and can forward the latest trap to configured destinations.

## GE Orbit radios

The Radios page polls a GE Orbit LN master (`mIfLnStatusConnRemTable`) and writes each connected radio into `Remote1` through `Remote255`. Every remote has the short tags (`remote_mac`, `remote_ip`, `rssi`, `down`, `if_index`) plus one tag per column of `mIfLnStatusConnRemEntry` in MDS-IF-LN-MIB. The master IP, community, port, and poll interval are set on the Config page.

The Send page can simulate those columns for Remote1 through Remote255 on one RSSI sine wave, with a random offset per remote. The wave period is 30 seconds and the step is 10 seconds. It stays stopped until you start it.

## OPC UA security

The server still accepts an anonymous session on security None. It also offers Basic256Sha256, Aes128-SHA256-RSA-OAEP, and Aes256-SHA256-RSA-PSS, in Sign and SignAndEncrypt. The application certificate is created on first start under `data/pki/own/`. A client certificate that is not trusted is stored in `data/pki/rejected` and can be accepted from the Publish page. Accepted certificates are stored in `data/pki/trusted/certs`. Accept, reject, and delete are written to disk and loaded again on the next start.

A username token is offered as well. On the open endpoint the password is encrypted with Basic256Sha256 and the server certificate. The first user is `trapsnmp` / `trapsnmp`.

## Settings

Communities, SNMPv3 users, the GE master, the agent, tag filters, upstream OPC UA, OPC UA users, and the last remote values are stored in `data/trapsnmp.ini` and loaded on the next start. The file is mode `0600`. Set `TRAPSNMP_DATA` to choose that folder. Otherwise an existing `/workspace/data` is used, then `./data`. The private key is not written into that file.

The console password is `P@ssw0rd`. It is stored in `[console]` of `data/trapsnmp.ini`. Use `P@ssw0rd` to sign in. Edit that line and restart only if you want a different password. Ten wrong passwords from one address lock it out for 5 minutes. Wrong passwords are forgotten after an hour, and a sign-in lasts 12 hours.

## Console HTTPS

`https://127.0.0.1:8888/` encrypts the password and the session cookie. `http://127.0.0.1:8888/` still works on the same port. If 8888 is also taken, set `TRAPSNMP_PORT` or `[console] port` and restart.

Chrome shows **Not secure** until Windows trusts the trapsnmp authority. Allowing the warning does not turn that into a padlock. After the gateway has been started once:

1. Download [https://127.0.0.1:8888/ca.crt](https://127.0.0.1:8888/ca.crt). The same file is `data/https/ca.crt`. The browser saves it as `trapsnmp-ca.crt`.
2. Open an Administrator PowerShell in the folder where that file was saved and run:

```powershell
certutil -addstore Root trapsnmp-ca.crt
```

3. Quit Chrome completely, then open `https://127.0.0.1:8888/` again.

The address bar then shows the lock. Until that authority is in Trusted Root, **Not secure** is normal. The authority certificate is valid for 15 years. The server certificate it signs is created on first start and is also valid for 15 years.

The RSSI sine stays stopped at startup. Start it from the Send page. Each step is 10 seconds.

## Running continuously

- Memory stays flat under steady trap traffic. Lists, logs, sessions, and queues all have fixed sizes.
- Each new trap OID or port number adds about 21 OPC UA nodes under `Tags`, and they are kept until restart. After 2,000 such addresses (about 42,000 nodes), new ones get no `TRAP_` tags; their traps still reach `Latest`, `Recent`, `EVENTS_001`–`EVENTS_010`, and the event, and the trace says "trap tag limit reached". Raise `MAX_TRAP_TAGS` in `trap_tags.py` if your devices need more.
- Each SNMPv3 sender engine ID gets its own copy of the user; at most 1,024 are kept, oldest dropped first.
- The OPC UA certificate is valid for 15 years. Within 30 days of expiry the gateway warns once a day in the log and trace, and a restart renews it (clients then trust the new one).
- An unreachable GE master is logged once when polling starts failing and once when it recovers.
- Logs go to standard output. Run the gateway under systemd or another service manager that rotates logs.
- The RSSI sine writes about 300 OPC UA nodes per trap (255 traps every 10 s). Leave it off on a production gateway.
