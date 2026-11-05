#!/usr/bin/env python3
"""Controlled Safari workload and transparent baseline relay; no TLS termination.

Run on the experiment Mac. SOCKS and HTTP CONNECT gates forward only --host:443
or a currently resolved IP of that host. The default backend is the plain relay
through --observe-port; --upstream-socks-port selects a real proxy SOCKS backend.
--normal-next-hop-port inserts a fixed loopback byte shim before the observer.
Capture only those observation ports. This process never changes system proxies.

bootstrap_download explores a normal counterexample constructed from a blind
analyst's multi-stage hypothesis; it is not a rendered page or independent
holdout. verified_bodies/body_bytes always describe completed HTTP response
bodies. POSTs send synthetic zero-filled arrays; a successful response does not
attest that the server received a particular upload byte count.
"""

import argparse
import asyncio
import datetime
import http.server
import ipaddress
import json
import os
import pathlib
import re
import signal
import socket
import threading
import urllib.parse


class LabHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def respond(self, body, content_type):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path in ("/browser.pac", "/parallax.pac"):
            port = self.server.args.normal_socks_port
            if parsed.path == "/parallax.pac":
                port = self.server.args.proxy_socks_port
            self.respond(
                "function FindProxyForURL(url, host) {\n"
                f"if (host === {json.dumps(self.server.args.host)}) "
                f'return "SOCKS 127.0.0.1:{port}";\n'
                'return "DIRECT";\n}\n',
                "application/x-ns-proxy-autoconfig",
            )
            return
        if parsed.path == "/health":
            self.respond(json.dumps({"host": self.server.args.host}), "application/json")
            return
        parts = parsed.path.strip("/").split("/")
        if parsed.path != "/workload" and not (len(parts) == 3 and parts[0] == "t"):
            self.send_error(404)
            return
        query = urllib.parse.parse_qs(parsed.query)
        if len(parts) == 3 and parts[0] == "t":
            query = {"trial": [parts[1]], "profile": [parts[2]]}
        trial = query.get("trial", [""])[0]
        profile = query.get("profile", ["single"])[0]
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", trial) or profile not in (
            "single", "browse", "interactive", "idle", "burst", "download", "upload", "page_download",
            "bootstrap_download"
        ):
            self.send_error(400)
            return
        if profile in ("download", "upload", "page_download", "bootstrap_download") and self.server.args.host != "speed.cloudflare.com":
            self.send_error(400, "bulk profiles require the verified speed endpoint")
            return
        config = json.dumps({"trial": trial, "profile": profile, "host": self.server.args.host})
        self.respond(
            "<!doctype html><meta charset=utf-8><title>Traffic lab running</title>"
            "<pre id=status>Running the controlled workload.</pre><script>\n"
            f"const c={config};\n"
            "const sleep=ms=>new Promise(r=>setTimeout(r,ms));\n"
            "const started=performance.now(); const result={...c,completed:0,"
            "verified_bodies:0,body_bytes:0,opaque_bodies:0,resource_protocols:[],errors:[]};\n"
            "async function request(i,step){\n"
            "let path='/?traffic_lab='+encodeURIComponent(c.trial)+'&request='+i;\n"
            "const options={mode:c.host==='speed.cloudflare.com'?'cors':'no-cors',cache:'no-store'};\n"
            "let expectedBytes=null;\n"
            "if(step){\n"
            "if(step.method==='GET')expectedBytes=step.bytes;\n"
            "else{path='/__up?trial='+c.trial+'&request='+i;"
            "options.method='POST';options.body=new Uint8Array(step.bytes);}}\n"
            "else if(c.profile==='upload'){path='/__up?trial='+c.trial+'&request='+i;"
            "options.method='POST';options.body=new Uint8Array(1048576);}\n"
            "else if(c.host==='speed.cloudflare.com'){expectedBytes=8192;"
            "if(c.profile==='download'||(c.profile==='page_download'&&i===1))expectedBytes=1048576;}\n"
            "if(expectedBytes!==null) path='/__down?bytes='+expectedBytes+'&trial='+c.trial+'&request='+i;\n"
            "const url='https://'+c.host+path;"
            "try{const r=await fetch(url,options);"
            "if(r.type==='opaque'){"
            "if(c.profile==='page_download'||c.profile==='bootstrap_download')"
            "throw new Error('verified response required');"
            "result.opaque_bodies++;}else{"
            "if(!r.ok)throw new Error('HTTP '+r.status);"
            "const body=await r.arrayBuffer();"
            "if(expectedBytes!==null&&body.byteLength!==expectedBytes)"
            "throw new Error('download byte count mismatch');"
            "result.body_bytes+=body.byteLength;result.verified_bodies++;}"
            "const timing=performance.getEntriesByName(url,'resource').at(-1);"
            "result.resource_protocols.push(timing?.nextHopProtocol||'unavailable');"
            "result.completed++;return true;}"
            "catch(e){result.errors.push(String(e));return false;}}\n"
            "(async()=>{\n"
            "if(c.profile==='bootstrap_download'){\n"
            "const steps=[{method:'POST',bytes:1536},{method:'GET',bytes:8192},"
            "{method:'POST',bytes:1536},{method:'GET',bytes:4096},{method:'GET',bytes:1048576}];\n"
            "for(let i=0;i<steps.length;i++){if(!await request(i,steps[i]))break;}}\n"
            "else if(c.profile==='burst') await Promise.all(Array.from({length:8},(_,i)=>request(i)));\n"
            "else{const n=({single:1,browse:8,interactive:12,idle:2,download:1,upload:1,page_download:2})[c.profile];"
            "for(let i=0;i<n;i++){const ok=await request(i);"
            "if(c.profile==='page_download'&&!ok)break;"
            "if(i+1<n&&c.profile!=='page_download')"
            "await sleep(c.profile==='idle'?5000:c.profile==='interactive'?300:100);}}\n"
            "result.elapsed_ms=performance.now()-started;"
            "const saved=await fetch('/done',{method:'POST',headers:{'Content-Type':'application/json'},"
            "body:JSON.stringify(result)});"
            "if(!saved.ok)throw new Error('Completion not saved: HTTP '+saved.status);"
            "if(c.profile==='bootstrap_download'&&result.errors.length)"
            "throw new Error('Bootstrap workload incomplete: '+result.errors[0]);"
            "document.title='Traffic lab done '+c.trial;"
            "document.getElementById('status').textContent=JSON.stringify(result,null,2);"
            "})().catch(e=>{document.title='Traffic lab failed';"
            "document.getElementById('status').textContent=String(e);});\n</script>",
            "text/html; charset=utf-8",
        )

    def do_POST(self):
        if self.path != "/done":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16384:
                raise ValueError("completion size")
            result = json.loads(self.rfile.read(size))
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", result["trial"]):
                raise ValueError("trial id")
            result["observed_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            path = self.server.args.output / (result["trial"] + ".json")
            with path.open("x") as output:
                json.dump(result, output, indent=2)
            self.respond("{}", "application/json")
        except (ValueError, KeyError, TypeError, FileExistsError):
            self.send_error(400)


async def pump(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()


async def bridge(reader, writer, upstream_reader, upstream_writer):
    try:
        await asyncio.wait_for(
            asyncio.gather(pump(reader, upstream_writer), pump(upstream_reader, writer)),
            timeout=90,
        )
    finally:
        await close_streams(writer, upstream_writer)


async def close_streams(*writers):
    for writer in writers:
        writer.close()
    try:
        await asyncio.wait_for(
            asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True),
            timeout=1,
        )
    except asyncio.TimeoutError:
        for writer in writers:
            writer.transport.abort()


def normalized_host(host):
    return host.lower().rstrip(".")


def normalized_ip(address):
    value = ipaddress.ip_address(address.split("%")[0])
    return str(value.ipv4_mapped or value) if isinstance(value, ipaddress.IPv6Address) else str(value)


async def resolve_allowed_origin(host):
    answers = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({normalized_ip(answer[4][0]) for answer in answers})


async def open_observed_origin(args):
    target = args.host
    if args.origin_ip is not None:
        target = normalized_ip(args.origin_ip)
        if target not in await resolve_allowed_origin(args.host):
            raise ValueError("pinned origin is outside the host's current DNS allowlist")
    return await asyncio.wait_for(asyncio.open_connection(target, 443), timeout=12)


async def read_socks_request(reader, writer):
    version, count = await reader.readexactly(2)
    methods = await reader.readexactly(count)
    if version != 5 or not count or 0 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        raise ValueError("unsupported SOCKS authentication")
    writer.write(b"\x05\x00")
    await writer.drain()
    version, command, reserved, atyp = await reader.readexactly(4)
    if (version, command, reserved) != (5, 1, 0):
        raise ValueError("unsupported SOCKS command")
    if atyp == 3:
        length = (await reader.readexactly(1))[0]
        if not length:
            raise ValueError("empty SOCKS hostname")
        host = (await reader.readexactly(length)).decode("ascii")
    elif atyp in (1, 4):
        host = str(ipaddress.ip_address(await reader.readexactly(4 if atyp == 1 else 16)))
    else:
        raise ValueError("unsupported SOCKS address type")
    port = int.from_bytes(await reader.readexactly(2), "big")
    return atyp, host, port


async def open_upstream_socks(port, connect_frame):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise ValueError("upstream SOCKS authentication rejected")
        writer.write(connect_frame)
        await writer.drain()
        version, reply, reserved, atyp = await reader.readexactly(4)
        if version != 5 or reserved != 0 or reply != 0:
            raise ValueError("upstream SOCKS CONNECT rejected")
        if atyp == 3:
            size = (await reader.readexactly(1))[0]
        elif atyp in (1, 4):
            size = 4 if atyp == 1 else 16
        else:
            raise ValueError("upstream SOCKS reply address invalid")
        await reader.readexactly(size + 2)
        return reader, writer
    except BaseException:
        writer.close()
        raise


def gate_diagnostic(args, outcome, atyp=None, matched=False, protocol="socks"):
    counters = getattr(args, "diagnostics", None)
    if counters is None:
        counters = args.diagnostics = {}
    key = protocol + ":" + outcome
    counters[key] = counters.get(key, 0) + 1
    if atyp is not None:
        key = "atyp_" + str(atyp)
        counters[key] = counters.get(key, 0) + 1
    print(json.dumps({"event": "scoped_" + protocol, "outcome": outcome, "atyp": atyp,
                      "whitelist_matched": matched, "counts": counters}), flush=True)


async def allowed_target(args, atyp, host, port):
    is_name = atyp == 3 and normalized_host(host) == normalized_host(args.host)
    if port != 443 or (atyp == 3 and not is_name):
        return False
    addresses = await resolve_allowed_origin(args.host)
    matched = is_name or normalized_ip(host) in addresses
    if matched:
        print(json.dumps({"event": "allowed_origin_resolution", "addresses": addresses,
                          "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
    return matched


async def connect_target(args, atyp, host):
    if atyp == 3:
        encoded = normalized_host(args.host).encode("ascii")
        address_frame = b"\x03" + bytes([len(encoded)]) + encoded
    else:
        address_frame = bytes([atyp]) + ipaddress.ip_address(host).packed
    connect_frame = b"\x05\x01\x00" + address_frame + b"\x01\xbb"
    if args.upstream_socks_port is None:
        port = args.normal_next_hop_port if args.normal_next_hop_port is not None else args.observe_port
        return await asyncio.open_connection("127.0.0.1", port)
    return await open_upstream_socks(args.upstream_socks_port, connect_frame)


async def handle_socks(reader, writer, args):
    atyp, matched = None, False
    upstream = None
    try:
        atyp, host, port = await asyncio.wait_for(read_socks_request(reader, writer), timeout=5)
        matched = await asyncio.wait_for(allowed_target(args, atyp, host, port), timeout=5)
        if not matched:
            gate_diagnostic(args, "policy_rejected", atyp)
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return
        upstream = await asyncio.wait_for(connect_target(args, atyp, host), timeout=5)
        gate_diagnostic(args, "allowed", atyp, True)
        writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        await writer.drain()
        await bridge(reader, writer, *upstream)
    except (OSError, UnicodeError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError):
        gate_diagnostic(args, "connection_failed", atyp, matched)
    finally:
        writer.close()
        if upstream:
            upstream[1].close()


async def handle_http_connect(reader, writer, args):
    atyp, matched, established = None, False, False
    upstream = None
    try:
        header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        if len(header) > 8192:
            raise ValueError("CONNECT header limit")
        method, authority, version = header.split(b"\r\n", 1)[0].decode("ascii").split(" ")
        if method != "CONNECT" or version not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("CONNECT method required")
        address = urllib.parse.urlsplit("//" + authority)
        if address.username is not None or address.password is not None or address.path or address.query or address.fragment:
            raise ValueError("invalid CONNECT authority")
        host, port = address.hostname, address.port
        if not host or port is None:
            raise ValueError("CONNECT port required")
        try:
            ip = ipaddress.ip_address(host)
            atyp = 1 if ip.version == 4 else 4
        except ValueError:
            atyp = 3
        matched = await asyncio.wait_for(allowed_target(args, atyp, host, port), timeout=5)
        if not matched:
            gate_diagnostic(args, "policy_rejected", atyp, protocol="http_connect")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        upstream = await asyncio.wait_for(connect_target(args, atyp, host), timeout=5)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        established = True
        gate_diagnostic(args, "allowed", atyp, True, protocol="http_connect")
        await bridge(reader, writer, *upstream)
    except (OSError, UnicodeError, ValueError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError, asyncio.TimeoutError):
        gate_diagnostic(args, "connection_failed", atyp, matched, protocol="http_connect")
        if not established:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            try:
                await writer.drain()
            except OSError:
                pass
    finally:
        writer.close()
        if upstream:
            upstream[1].close()


async def serve(args):
    active = set()
    stop = asyncio.Event()

    async def tracked(handler, reader, writer):
        if stop.is_set():
            await close_streams(writer)
            return
        task = asyncio.current_task()
        active.add(task)
        try:
            await handler(reader, writer)
        finally:
            writer.close()
            active.discard(task)

    async def observe(reader, writer):
        try:
            upstream = await open_observed_origin(args)
            print(json.dumps({"baseline_tls_connection": True, "host": args.host,
                              "actual_origin_peer": upstream[1].get_extra_info("peername")}), flush=True)
            await bridge(reader, writer, *upstream)
        except (OSError, ValueError, asyncio.TimeoutError):
            writer.close()

    async def socks(reader, writer):
        await handle_socks(reader, writer, args)

    async def http_connect(reader, writer):
        await handle_http_connect(reader, writer, args)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async with (
        await asyncio.start_server(lambda r, w: tracked(observe, r, w),
                                   "127.0.0.1", args.observe_port) as observer,
        await asyncio.start_server(lambda r, w: tracked(socks, r, w),
                                   "127.0.0.1", args.normal_socks_port) as socks_gate,
        await asyncio.start_server(lambda r, w: tracked(http_connect, r, w),
                                   "127.0.0.1", args.http_connect_port, limit=8192) as connect_gate,
    ):
        print(json.dumps({"ready": True, "host": args.host, "observe_port": args.observe_port,
                          "http_connect_port": args.http_connect_port,
                          "origin_ip": args.origin_ip,
                          "normal_next_hop_port": args.normal_next_hop_port,
                          "upstream_socks_port": args.upstream_socks_port}), flush=True)
        await stop.wait()
        # Python 3.14's Server.wait_closed waits for accepted connections. Stop
        # those handlers before the context managers await server shutdown.
        for server in (observer, socks_gate, connect_gate):
            server.close()
        tasks = list(active)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def drop_bind_privilege(parser):
    if os.geteuid() != 0:
        return
    try:
        uid = int(os.environ.get("SUDO_UID", "0"))
        gid = int(os.environ.get("SUDO_GID", "0"))
    except ValueError:
        parser.error("sudo caller IDs must be integers")
    if uid <= 0 or gid <= 0:
        parser.error("root launch requires an unprivileged sudo caller")
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def validate_ports(args, parser):
    listeners = (args.observe_port, args.normal_socks_port, args.http_connect_port, args.pac_port)
    for port in (*listeners, args.proxy_socks_port, args.upstream_socks_port, args.normal_next_hop_port):
        if port is not None and not 1 <= port <= 65535:
            parser.error("relay ports must be in 1..65535")
    if len(set(listeners)) != len(listeners):
        parser.error("helper listener ports must be distinct")
    if args.upstream_socks_port is not None and args.normal_next_hop_port is not None:
        parser.error("upstream-socks-port and normal-next-hop-port are mutually exclusive")
    if any(port in listeners for port in (args.upstream_socks_port, args.normal_next_hop_port)
           if port is not None):
        parser.error("backend cannot point to a helper listener (direct self-loop)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--origin-ip", type=normalized_ip,
                        help="pin only the baseline observer to a current DNS address of --host")
    parser.add_argument("--observe-port", type=int, default=58444)
    parser.add_argument("--normal-socks-port", type=int, default=1081)
    parser.add_argument("--proxy-socks-port", type=int, default=1080)
    parser.add_argument("--upstream-socks-port", type=int,
                        help="forward whitelist-approved CONNECT through this loopback SOCKS server")
    parser.add_argument("--normal-next-hop-port", type=int,
                        help="normal backend only: fixed loopback byte shim before the observer")
    parser.add_argument("--http-connect-port", type=int, default=1082)
    parser.add_argument("--pac-port", type=int, default=18777)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", args.host):
        parser.error("--host must be a DNS hostname")
    args.host = normalized_host(args.host)
    validate_ports(args, parser)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.pac_port), LabHandler)
    # Bind a low HTTP port first, then serve and create artifacts as the caller.
    drop_bind_privilege(parser)
    args.output.mkdir(parents=True, exist_ok=True)
    httpd.args = args
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        asyncio.run(serve(args))
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
