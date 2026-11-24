"""Operator console served next to the gateway."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trapsnmp.catalog import PRESETS
from trapsnmp.service import Service
from trapsnmp.settings import data_dir

log = logging.getLogger("trapsnmp.web")

STATIC = Path(__file__).resolve().parent / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
_COOKIE = "trapsnmp"
_SESSION_SECONDS = 12 * 60 * 60
_MAX_SESSIONS = 100
_FAIL_DELAY = 1.0
_FAIL_LIMIT = 10
_LOCKOUT_SECONDS = 5 * 60
_FAIL_FORGET_SECONDS = 60 * 60  # wrong passwords older than this no longer count
_ADDRESS_LOCKS: dict[str, asyncio.Lock] = {}


def _preset_buttons(items) -> str:
    parts = []
    for item in items:
        parts.append(
            "<button type=\"button\" class=\"preset\" data-preset=\"{id}\">"
            "<span class=\"preset-name\">{label}</span>"
            "<span class=\"preset-detail\">{detail}</span>"
            "</button>".format(
                id=_esc(item["id"]),
                label=_esc(item["label"]),
                detail=_esc(item["detail"]),
            )
        )
    return "".join(parts)


def _esc(value: str) -> str:
    return escape(value, quote=True)


PAGE = INDEX.replace(
    "<!--PRESETS-->",
    _preset_buttons([item for item in PRESETS if item.get("group") != "ge-ln"]),
).replace(
    "<!--GE-PRESETS-->",
    _preset_buttons([item for item in PRESETS if item.get("group") == "ge-ln"]),
)


def _json_error(message: str, status: int = 400) -> web.Response:
    return web.json_response({"ok": False, "error": message}, status=status)


@web.middleware
async def _json_posts(request: web.Request, handler):
    # A page on another site can POST text/plain without a CORS preflight,
    # and request.json() would still parse it. Only application/json is accepted.
    if request.method == "POST" and request.content_type != "application/json":
        return _json_error("Send JSON with Content-Type: application/json.", 415)
    return await handler(request)


def _password_ok(got: str, expected: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(got.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )


def _open_path(request: web.Request) -> bool:
    if request.method == "GET" and (
        request.path in ("/", "/favicon.svg", "/ca.crt", "/ca.cer", "/trust-windows.bat") or request.path.startswith("/static/")
    ):
        return True
    return request.method == "POST" and request.path == "/api/login"


def _new_session(sessions: dict[str, float]) -> str:
    now = time.monotonic()
    for token, expires in list(sessions.items()):
        if expires <= now:
            del sessions[token]
    while len(sessions) >= _MAX_SESSIONS:
        del sessions[min(sessions, key=sessions.get)]
    token = secrets.token_urlsafe(32)
    sessions[token] = now + _SESSION_SECONDS
    return token


@web.middleware
async def _require_login(request: web.Request, handler):
    if _open_path(request):
        return await handler(request)
    token = request.cookies.get(_COOKIE, "")
    sessions: dict[str, float] = request.app["sessions"]
    expires = sessions.get(token) if token else None
    if expires is not None and expires > time.monotonic():
        return await handler(request)
    if expires is not None:
        sessions.pop(token, None)
    return _json_error("Sign in required.", 401)


def _forget_old_failures(failures: dict[str, tuple[int, float, float]], now: float) -> None:
    for key, (_count, until, last) in list(failures.items()):
        if until <= now and now - last > _FAIL_FORGET_SECONDS:
            del failures[key]
            gate = _ADDRESS_LOCKS.get(key)
            if gate is not None and not gate.locked():
                _ADDRESS_LOCKS.pop(key, None)


async def _check_login(request, service, body, failures, address, gate) -> web.Response:
    async with gate:
        now = time.monotonic()
        count, locked_until, _last = failures.get(address, (0, 0.0, 0.0))
        if locked_until > now:
            minutes = max(1, round((locked_until - now) / 60))
            return _json_error(f"Too many wrong passwords. Try again in {minutes} min.", 429)
        if not _password_ok(str(body.get("password") or ""), service.console_password):
            count += 1
            locked_until = now + _LOCKOUT_SECONDS if count >= _FAIL_LIMIT else 0.0
            failures[address] = (0 if locked_until else count, locked_until, now)
            if locked_until:
                log.warning("console sign-in locked for %s after %s wrong passwords", address, count)
            await asyncio.sleep(_FAIL_DELAY)
            if locked_until:
                return _json_error("Too many wrong passwords. Try again in 5 min.", 429)
            return _json_error("Wrong password.", 401)
        failures.pop(address, None)
        token = _new_session(request.app["sessions"])
    response = web.json_response({"ok": True})
    response.set_cookie(
        _COOKIE,
        token,
        httponly=True,
        samesite="Lax",
        path="/",
        max_age=_SESSION_SECONDS,
        secure=request.secure,
    )
    return response


async def handle_login(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    failures: dict[str, tuple[int, float, float]] = request.app["login_failures"]
    address = request.remote or "?"
    _forget_old_failures(failures, time.monotonic())
    gate = _ADDRESS_LOCKS.setdefault(address, asyncio.Lock())
    try:
        return await _check_login(request, service, body, failures, address, gate)
    finally:
        if address not in failures and not gate.locked() and not getattr(gate, "_waiters", None):
            _ADDRESS_LOCKS.pop(address, None)


async def handle_logout(request: web.Request) -> web.Response:
    token = request.cookies.get(_COOKIE, "")
    request.app["sessions"].pop(token, None)
    response = web.json_response({"ok": True})
    response.del_cookie(_COOKIE, path="/")
    return response


async def handle_ca(request: web.Request) -> web.Response:
    folder = data_dir() / "https"
    der = request.path.endswith(".cer")
    path = folder / ("ca.cer" if der else "ca.crt")
    if not path.is_file():
        return web.Response(status=404, text="Certificate is not ready yet.")
    filename = "trapsnmp-ca.cer" if der else "trapsnmp-ca.crt"
    return web.Response(
        body=path.read_bytes(),
        content_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def handle_trust_bat(_request: web.Request) -> web.Response:
    folder = data_dir() / "https"
    cer = folder / "ca.cer"
    if not cer.is_file():
        crt = folder / "ca.crt"
        if not crt.is_file():
            return web.Response(status=404, text="Certificate is not ready yet.")
        loaded = x509.load_pem_x509_certificate(crt.read_bytes())
        cer.write_bytes(loaded.public_bytes(serialization.Encoding.DER))
    encoded = base64.b64encode(cer.read_bytes()).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    body = "\r\n".join(
        [
            "@echo off",
            "net session >nul 2>&1",
            "if not %ERRORLEVEL%==0 (",
            "  powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
            "  exit /b",
            ")",
            "set \"B64=%TEMP%\\trapsnmp-ca.b64\"",
            "set \"CER=%TEMP%\\trapsnmp-ca.cer\"",
            "> \"%B64%\" (",
            "echo -----BEGIN CERTIFICATE-----",
            *[f"echo {line}" for line in lines],
            "echo -----END CERTIFICATE-----",
            ")",
            "certutil -decode \"%B64%\" \"%CER%\"",
            "if errorlevel 1 (",
            "  echo Could not decode the authority.",
            "  pause",
            "  exit /b 1",
            ")",
            "certutil -addstore Root \"%CER%\"",
            "if errorlevel 1 (",
            "  echo Could not add the authority to Trusted Root.",
            "  pause",
            "  exit /b 1",
            ")",
            "echo.",
            "echo Windows now trusts the trapsnmp console.",
            "echo Quit Chrome completely, then open https://127.0.0.1:8888/ again.",
            "echo Closing one tab is not enough.",
            "pause",
            "",
        ]
    )
    return web.Response(
        body=body.encode("ascii"),
        content_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="trust-windows.bat"'},
    )


async def handle_index(_request: web.Request) -> web.Response:
    return web.Response(
        text=PAGE,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


async def handle_opc_user(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        if body.get("action") == "remove":
            service.opc.users.remove(str(body.get("name") or ""))
        else:
            password = body.get("password")
            if not isinstance(password, str):
                raise ValueError("Password must be 8–64 characters.")
            service.opc.users.add(str(body.get("name") or ""), password)
    except ValueError as exc:
        return _json_error(str(exc))
    service.persist()
    return web.json_response({"ok": True, "users": service.opc.users.names()})


async def handle_pki(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    if service.opc.pki is None:
        return _json_error("The certificate store is not ready.", 503)
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    action = str(body.get("action") or "")
    name = str(body.get("name") or "")
    try:
        if action == "trust":
            summary = service.opc.pki.trust(name)
        elif action == "reject":
            summary = service.opc.pki.reject(name)
        elif action == "delete":
            summary = service.opc.pki.delete(name, str(body.get("list") or ""))
        else:
            return _json_error("Expected a trust, reject, or delete action.")
    except ValueError as exc:
        return _json_error(str(exc))
    return web.json_response({"ok": True, "certificate": summary})


async def handle_readback(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        return _json_error("Expected enabled true or false.")
    try:
        await service.opc.set_readback(body["enabled"])
    except Exception as exc:
        return _json_error(str(exc) or "Could not change the internal session.")
    service.persist()
    stopped = not service.opc.readback_enabled
    service._trace("Internal readback stopped" if stopped else "Internal readback started")
    return web.json_response({"ok": True, "enabled": service.opc.readback_enabled, "stopped": stopped})


async def handle_opc(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    folder = request.query.get("folder", "Latest")
    query = request.query.get("q", "")
    return web.json_response(await service.opc.browse(folder, query))


async def handle_favicon(_request: web.Request) -> web.Response:
    body = (STATIC / "favicon.svg").read_bytes()
    return web.Response(body=body, content_type="image/svg+xml")


async def handle_state(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    response = web.json_response(await service.snapshot())
    response.enable_compression()
    return response


async def handle_inject(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        preset = body.get("preset")
        if preset:
            record = await service.inject_preset(str(preset), _optional_str(body.get("community")))
        else:
            binds = []
            for item in body.get("varbinds") or []:
                if not isinstance(item, dict):
                    raise ValueError("Each varbind needs oid, type, and value.")
                binds.append(
                    (
                        str(item.get("oid", "")).strip(),
                        str(item.get("type", "string")).strip(),
                        str(item.get("value", "")),
                    )
                )
            record = await service.inject_custom(
                community=str(body.get("community") or "public"),
                version=str(body.get("version") or "2c"),
                trap_oid=str(body.get("trapOid") or "").strip(),
                varbinds=binds,
                user=_optional_str(body.get("user")),
            )
    except (ValueError, RuntimeError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("inject failed")
        return _json_error(str(exc), 500)
    return web.json_response({"ok": True, "trap": record})


async def handle_community(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        service.allow_community(str(body.get("community", "")))
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "communities": service.snmp.communities})


async def handle_user(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        created = service.add_user(body if isinstance(body, dict) else {})
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "user": created, "users": service.snmp.users})


async def handle_diag(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        report = await service.diagnose()
    except Exception as exc:
        log.exception("diag failed")
        return _json_error(str(exc), 500)
    return web.json_response(report)


async def handle_agent(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    action = str(body.get("action") or "settings")
    try:
        if action == "settings":
            service.agent.configure(body)
        elif action == "community":
            service.agent.add_community(str(body.get("name") or ""), str(body.get("rights") or ""))
        elif action == "host":
            service.agent.add_host(str(body.get("address") or ""))
        elif action == "destination":
            service.agent.add_destination(
                str(body.get("address") or ""),
                int(body.get("port") or 162),
                str(body.get("community") or "public"),
                str(body.get("version") or "2c"),
            )
        elif action == "remove":
            service.agent.remove(str(body.get("kind") or ""), str(body.get("key") or ""))
        else:
            raise ValueError("Unknown agent action.")
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("agent update failed")
        return _json_error(str(exc), 500)
    service.persist()
    return web.json_response({"ok": True, "agent": service.agent.snapshot()})


async def handle_radios(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    action = str(body.get("action") or "save")
    try:
        if action in ("save", "poll"):
            service.radios.configure(
                host=str(body.get("host") or ""),
                community=str(body.get("community") or "public"),
                port=int(body.get("port") or 161),
                interval=int(body.get("interval") or 15),
                enabled=bool(body.get("enabled")),
            )
        if action == "poll":
            await service.radios.poll()
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("radio poll failed")
        return _json_error(str(exc), 500)
    return web.json_response({"ok": True, "radios": service.radio_view()})


async def handle_windows_service(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    enabled = bool(body.get("enabled"))
    try:
        from trapsnmp.win_service import apply

        report = apply(enabled)
    except ValueError as exc:
        return _json_error(str(exc))
    except Exception as exc:
        log.exception("windows service change failed")
        return _json_error(str(exc), 500)
    service.windows_service = enabled
    service.persist()
    service._trace(report.get("detail") or ("Windows service on" if enabled else "Windows service off"))
    return web.json_response({"ok": True, "windowsService": report})


async def handle_tags(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    try:
        service.tags.configure(
            community=str(body.get("community") or ""),
            device_ip=str(body.get("deviceIp") or ""),
        )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc))
    service.persist()
    return web.json_response({"ok": True, "tags": service.tags.snapshot()})


async def handle_sine(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
    except Exception:
        return _json_error("Expected JSON.")
    if not isinstance(body, dict):
        return _json_error("Expected a JSON object.")
    return web.json_response({"ok": True, "sine": service.set_sine(bool(body.get("enabled")))})


async def handle_upstream(request: web.Request) -> web.Response:
    service: Service = request.app["service"]
    try:
        body = await request.json()
        service.configure_upstream(
            enabled=bool(body.get("enabled")),
            endpoint=str(body.get("endpoint") or ""),
            node_id=str(body.get("nodeId") or ""),
        )
    except (ValueError, TypeError, AttributeError) as exc:
        return _json_error(str(exc))
    except Exception:
        return _json_error("Expected JSON.", 400)
    service.persist()
    return web.json_response({"ok": True, "upstream": service.opc.upstream})


def _optional_str(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


async def serve(service: Service) -> None:
    app = web.Application(client_max_size=1024 * 256, middlewares=[_json_posts, _require_login])
    app["service"] = service
    app["sessions"] = {}
    app["login_failures"] = {}
    app.router.add_get("/", handle_index)
    app.router.add_get("/ca.crt", handle_ca)
    app.router.add_get("/ca.cer", handle_ca)
    app.router.add_get("/trust-windows.bat", handle_trust_bat)
    app.router.add_get("/favicon.svg", handle_favicon)
    app.router.add_post("/api/login", handle_login)
    app.router.add_post("/api/logout", handle_logout)
    app.router.add_get("/api/state", handle_state)
    app.router.add_get("/api/opc", handle_opc)
    app.router.add_post("/api/pki", handle_pki)
    app.router.add_post("/api/opc-user", handle_opc_user)
    app.router.add_post("/api/inject", handle_inject)
    app.router.add_post("/api/community", handle_community)
    app.router.add_post("/api/user", handle_user)
    app.router.add_post("/api/diag", handle_diag)
    app.router.add_post("/api/agent", handle_agent)
    app.router.add_post("/api/tags", handle_tags)
    app.router.add_post("/api/radios", handle_radios)
    app.router.add_post("/api/windows-service", handle_windows_service)
    app.router.add_post("/api/sine", handle_sine)
    app.router.add_post("/api/readback", handle_readback)
    app.router.add_post("/api/upstream", handle_upstream)
    app.router.add_static("/static", STATIC, show_index=False)
    runner = web.AppRunner(app)
    await runner.setup()
    try:
        context = _console_ssl()
    except Exception:
        log.exception("HTTPS certificate failed; console stays on HTTP only")
        site = web.TCPSite(runner, "0.0.0.0", _console_port(service))
        await site.start()
        log.info("console ready at http://127.0.0.1:%s/", _console_port(service))
        await asyncio_forever()
        return
    await _serve_http_and_https(runner.server, context, _console_port(service))


async def _serve_http_and_https(factory, ssl_context: ssl.SSLContext, port: int) -> None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(128)
    sock.setblocking(False)
    log.info("console ready at http://127.0.0.1:%s/ and https://127.0.0.1:%s/", port, port)
    while True:
        client, _addr = await loop.sock_accept(sock)
        asyncio.create_task(_hand_console(loop, client, factory, ssl_context))


def _console_port(service: Service) -> int:
    raw = os.environ.get("TRAPSNMP_PORT", "").strip()
    if raw:
        try:
            picked = int(raw)
        except ValueError:
            picked = 0
        if 1 <= picked <= 65535:
            return picked
    port = int(getattr(service, "console_port", 8888) or 8888)
    return port if 1 <= port <= 65535 else 8888


def _peek_first(sock: socket.socket) -> bytes:
    sock.settimeout(30)
    try:
        return sock.recv(1, socket.MSG_PEEK)
    except (TimeoutError, socket.timeout, OSError):
        return b""


async def _hand_console(loop, client: socket.socket, factory, ssl_context: ssl.SSLContext) -> None:
    try:
        first = await loop.run_in_executor(None, _peek_first, client)
        client.setblocking(False)
        if not first:
            client.close()
            return
        if first == b"\x16":
            await loop.connect_accepted_socket(
                factory, client, ssl=ssl_context, ssl_handshake_timeout=30
            )
        else:
            await loop.connect_accepted_socket(factory, client)
    except Exception as exc:
        log.warning("console connection failed: %s", exc)
        try:
            client.close()
        except Exception:
            pass


def _console_ssl() -> ssl.SSLContext:
    folder = data_dir() / "https"
    folder.mkdir(parents=True, exist_ok=True)
    cert_file = folder / "cert.pem"
    key_file = folder / "key.pem"
    if not cert_file.is_file() or not key_file.is_file() or not _cert_is_server(cert_file):
        _write_console_cert(cert_file, key_file)
        log.info("Console HTTPS certificate is %s", cert_file)
    _ensure_console_chain(folder)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(folder / "chain.pem", key_file)
    return context


def _write_console_cert(cert_file: Path, key_file: Path) -> None:
    folder = cert_file.parent
    ca_key, ca_cert = _console_ca(folder)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = [x509.DNSName("localhost")]
    addresses = [ipaddress.IPv4Address("127.0.0.1"), ipaddress.IPv6Address("::1")]
    host = socket.gethostname() or ""
    if host and host.lower() != "localhost":
        try:
            names.append(x509.DNSName(host))
        except ValueError:
            pass
        try:
            addresses.append(ipaddress.ip_address(socket.gethostbyname(host)))
        except (OSError, ValueError):
            pass
    alt = list(names) + [x509.IPAddress(item) for item in dict.fromkeys(addresses)]
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=15 * 365))
        .add_extension(x509.SubjectAlternativeName(alt), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _ensure_console_chain(folder)


def _ensure_console_chain(folder: Path) -> None:
    certificate = (folder / "cert.pem").read_bytes().rstrip() + b"\n"
    authority = (folder / "ca.crt").read_bytes()
    (folder / "chain.pem").write_bytes(certificate + authority)
    cer = folder / "ca.cer"
    if not cer.is_file():
        loaded = x509.load_pem_x509_certificate(authority)
        cer.write_bytes(loaded.public_bytes(serialization.Encoding.DER))


def _console_ca(folder: Path):
    key_file = folder / "ca.key"
    cert_file = folder / "ca.crt"
    if key_file.is_file() and cert_file.is_file():
        key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
        return key, x509.load_pem_x509_certificate(cert_file.read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "trapsnmp console"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "trapsnmp"),
    ])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=15 * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    descriptor = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (folder / "ca.cer").write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    return key, certificate


def _cert_is_server(path: Path) -> bool:
    try:
        certificate = x509.load_pem_x509_certificate(path.read_bytes())
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        authority = x509.load_pem_x509_certificate((path.parent / "ca.crt").read_bytes())
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        has_loopback = ipaddress.IPv6Address("::1") in names.get_values_for_type(x509.IPAddress)
    except Exception:
        return False
    return (
        x509.ExtendedKeyUsageOID.SERVER_AUTH in usage
        and certificate.issuer == authority.subject
        and has_loopback
    )


async def asyncio_forever() -> None:
    import asyncio

    await asyncio.Event().wait()
