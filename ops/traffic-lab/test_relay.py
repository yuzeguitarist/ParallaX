"""Whitelist/forwarding and actual emitted browser-JS regressions; no external network."""

import asyncio
import argparse
import contextlib
import http.client
import io
import ipaddress
import json
import pathlib
import re
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

import relay


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def reader_for(data):
    reader = asyncio.StreamReader(limit=8192)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def arguments(**overrides):
    return types.SimpleNamespace(**{"host": "example.com", "origin_ip": None, "observe_port": 58444,
                                   "normal_socks_port": 1081, "proxy_socks_port": 1080,
                                   "upstream_socks_port": None, "http_connect_port": 1082,
                                   "normal_next_hop_port": None, "pac_port": 18777,
                                   "output": pathlib.Path("unused"), **overrides})


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_normal_next_hop_is_fixed_and_default_and_proxy_backends_keep_their_paths(self):
        streams = (object(), object())
        for next_hop, expected in ((None, 58444), (58454, 58454)):
            with mock.patch.object(relay.asyncio, "open_connection", mock.AsyncMock(return_value=streams)) as connect:
                self.assertIs(await relay.connect_target(arguments(normal_next_hop_port=next_hop), 3, "example.com"), streams)
                connect.assert_awaited_once_with("127.0.0.1", expected)
        with mock.patch.object(relay, "open_upstream_socks", mock.AsyncMock(return_value=streams)) as connect:
            self.assertIs(await relay.connect_target(arguments(upstream_socks_port=1080), 3, "example.com"), streams)
            self.assertEqual(connect.await_args.args[0], 1080)

    async def test_normal_next_hop_real_connect_still_validates_dns_before_dialing(self):
        received = asyncio.get_running_loop().create_future()
        async def upstream(reader, writer):
            try:
                data = await reader.read()
                received.set_result(data)
                writer.write(b"late reply")
                await writer.drain()
            finally:
                await relay.close_streams(writer)
        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        args = arguments(normal_next_hop_port=port)
        gate = await asyncio.start_server(lambda r, w: relay.handle_http_connect(r, w, args), "127.0.0.1", 0)
        try:
            with mock.patch.object(relay, "resolve_allowed_origin", mock.AsyncMock(return_value=["203.0.113.8"])) as resolve, \
                 contextlib.redirect_stdout(io.StringIO()):
                reader, writer = await asyncio.open_connection("127.0.0.1", gate.sockets[0].getsockname()[1])
                writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
                await writer.drain()
                self.assertIn(b"200", await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1))
                writer.write(b"unchanged bytes")
                writer.write_eof()
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"late reply")
                self.assertEqual(await received, b"unchanged bytes")
                resolve.assert_awaited_once_with("example.com")
                await relay.close_streams(writer)
        finally:
            gate.close()
            server.close()
            await gate.wait_closed()
            await server.wait_closed()

    async def test_observer_pin_is_dns_allowlisted_and_preserves_the_plain_stream(self):
        streams = (object(), object())
        for configured, expected in ((None, "example.com"), ("2001:0db8::8", "2001:db8::8")):
            with self.subTest(configured=configured), \
                 mock.patch.object(relay, "resolve_allowed_origin", mock.AsyncMock(return_value=["2001:db8::8"])) as resolve, \
                 mock.patch.object(relay.asyncio, "open_connection", mock.AsyncMock(return_value=streams)) as connect:
                self.assertIs(await relay.open_observed_origin(arguments(origin_ip=configured)), streams)
                connect.assert_awaited_once_with(expected, 443)
                self.assertEqual(resolve.await_count, int(configured is not None))

    async def test_observer_never_connects_a_pin_outside_the_current_origin_allowlist(self):
        with mock.patch.object(relay, "resolve_allowed_origin", mock.AsyncMock(return_value=["203.0.113.8"])), \
             mock.patch.object(relay.asyncio, "open_connection", mock.AsyncMock()) as connect:
            with self.assertRaisesRegex(ValueError, "DNS allowlist"):
                await relay.open_observed_origin(arguments(origin_ip="198.51.100.9"))
            connect.assert_not_awaited()

    async def test_shutdown_aborts_a_peer_that_never_finishes_closing(self):
        writer = mock.Mock()
        async def blocked_close():
            await asyncio.Future()
        writer.wait_closed = mock.AsyncMock(side_effect=blocked_close)
        await asyncio.wait_for(relay.close_streams(writer), timeout=2)
        writer.close.assert_called_once()
        writer.transport.abort.assert_called_once()

    async def run_socks(self, atyp, address, allowed_ips, host_port=443):
        frame = b"\x05\x01\x00\x05\x01\x00" + bytes([atyp]) + address + host_port.to_bytes(2, "big")
        writer, upstream = MemoryWriter(), MemoryWriter()
        logs = io.StringIO()
        with mock.patch.object(relay, "resolve_allowed_origin", mock.AsyncMock(return_value=allowed_ips)) as resolve, \
             mock.patch.object(relay, "connect_target", mock.AsyncMock(return_value=(None, upstream))) as connect, \
             mock.patch.object(relay, "bridge", mock.AsyncMock()), contextlib.redirect_stdout(logs):
            await relay.handle_socks(reader_for(frame), writer, arguments())
        return writer, resolve, connect, logs.getvalue()

    async def test_domain_case_and_trailing_dot_and_ip_allowlist(self):
        for atyp, address, ips in (
            (3, b"\x0cEXAMPLE.COM.", ["203.0.113.8"]),
            (1, ipaddress.ip_address("203.0.113.8").packed, ["203.0.113.8"]),
            (4, ipaddress.ip_address("2001:db8::8").packed, ["2001:db8::8"]),
        ):
            writer, resolve, connect, _ = await self.run_socks(atyp, address, ips)
            self.assertEqual(writer.data[2:4], b"\x05\x00")
            self.assertTrue(writer.closed)
            resolve.assert_awaited_once_with("example.com")
            connect.assert_awaited_once()

    async def test_rejected_targets_are_neither_connected_nor_logged(self):
        rejected = "private-do-not-log.invalid"
        writer, resolve, connect, logs = await self.run_socks(
            3, bytes([len(rejected)]) + rejected.encode(), ["203.0.113.8"])
        self.assertEqual(writer.data[2:4], b"\x05\x02")
        self.assertNotIn(rejected, logs)
        resolve.assert_not_awaited()
        connect.assert_not_awaited()
        writer, _, connect, logs = await self.run_socks(
            1, ipaddress.ip_address("198.51.100.9").packed, ["203.0.113.8"])
        self.assertEqual(writer.data[2:4], b"\x05\x02")
        self.assertNotIn("198.51.100.9", logs)
        connect.assert_not_awaited()

    async def test_upstream_no_auth_connect_reply_is_consumed_without_eating_data(self):
        upstream = MemoryWriter()
        response = reader_for(b"\x05\x00\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00payload")
        frame = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb"
        with mock.patch.object(relay.asyncio, "open_connection", mock.AsyncMock(return_value=(response, upstream))):
            reader, _ = await relay.open_upstream_socks(1080, frame)
        self.assertEqual(upstream.data, b"\x05\x01\x00" + frame)
        self.assertEqual(await reader.read(), b"payload")

    async def test_http_connect_shares_the_gate_and_rejects_other_methods_targets(self):
        for authority, expected in (("EXAMPLE.COM.:443", 200), ("other.invalid:443", 403),
                                     ("example.com:80", 403)):
            writer, upstream = MemoryWriter(), MemoryWriter()
            with mock.patch.object(relay, "resolve_allowed_origin", mock.AsyncMock(return_value=["203.0.113.8"])), \
                 mock.patch.object(relay, "connect_target", mock.AsyncMock(return_value=(None, upstream))) as connect, \
                 mock.patch.object(relay, "bridge", mock.AsyncMock()), contextlib.redirect_stdout(io.StringIO()):
                await relay.handle_http_connect(reader_for(
                    f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()), writer, arguments())
            self.assertIn(str(expected).encode(), writer.data.split(b"\r\n")[0])
            self.assertEqual(connect.await_count, int(expected == 200))
        for request in (b"GET / HTTP/1.1\r\n\r\n", b"CONNECT example.com:443 HTTP/1.1\r\nX: " + b"x"*9000 + b"\r\n\r\n"):
            writer = MemoryWriter()
            with contextlib.redirect_stdout(io.StringIO()):
                await relay.handle_http_connect(reader_for(request), writer, arguments())
            self.assertTrue(writer.data.startswith(b"HTTP/1.1 400"))


NODE_RUNNER = r"""
const fs=require('fs'), vm=require('vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
let reads=0,bodyResolved=false,done=null;
const requests=[],bodySizes=[],sleeps=[];
const timings=[{name:'https://unrelated.invalid/private',entryType:'resource',nextHopProtocol:'h3'}];
const state={title:'',textContent:''};
const context={Uint8Array,performance:{now:()=>10,
getEntriesByName:(name,type)=>timings.filter(t=>t.name===name&&t.entryType===type)},
setTimeout:(f,ms)=>{sleeps.push(ms);queueMicrotask(f);return 0},
document:{get title(){return state.title},set title(v){state.title=v},getElementById:()=>state},
fetch:async(url,options)=>{
 if(url==='/done'){done={result:JSON.parse(options.body),reads,bodyResolved,requests,bodySizes,sleeps};
 const status=input.completion_status;return {ok:status>=200&&status<300,status};}
 const response=input.responses?input.responses[requests.length]:input;
 requests.push({url,method:options.method||'GET',mode:options.mode,resolvedBodies:bodySizes.length,
 bodyLength:options.body?.byteLength||0,bodyAllZero:options.body?options.body.every(b=>b===0):null});
 if(!response)throw Error('unexpected additional request');
 if(response.scenario==='fetch_error')throw Error('network request failed');
 const opaque=response.scenario==='opaque',ok=response.scenario!=='bad_status';
 return {type:opaque?'opaque':'cors',ok,status:ok?200:503,
 arrayBuffer:async()=>{reads++;if(opaque)throw Error('opaque body was read');
 await new Promise(resolve=>setImmediate(resolve));
 if(response.scenario==='body_error')throw Error('truncated response body');
 bodyResolved=true;
 bodySizes.push(response.bytes);
 if(!response.missingTiming)timings.push({name:url,entryType:'resource',
 nextHopProtocol:response.protocol===undefined?'h2':response.protocol});
 return new ArrayBuffer(response.bytes);}};
}};
vm.runInNewContext(input.script,context,{timeout:1000});
(async()=>{for(let i=0;i<200&&!(done&&/Traffic lab (done|failed)/.test(state.title));i++)
 await new Promise(resolve=>setImmediate(resolve));
 if(!done||!/Traffic lab (done|failed)/.test(state.title))throw Error('emitted workload never completed');
 process.stdout.write(JSON.stringify({...done,title:state.title,display:state.textContent}));
})().catch(e=>{process.stderr.write(String(e));process.exitCode=1;});
"""


class BrowserWorkloadTests(unittest.TestCase):
    def emitted_page(self, host, profile):
        server = relay.http.server.ThreadingHTTPServer(("127.0.0.1", 0), relay.LabHandler)
        server.args = arguments(host=host)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request("GET", "/t/testtrial/" + profile)
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join()

    def execute(self, host, profile, scenario, byte_count, completion_status=200, responses=None):
        status, html = self.emitted_page(host, profile)
        self.assertEqual(status, 200)
        script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
        result = subprocess.run(["node", "-e", NODE_RUNNER],
                                input=json.dumps({"script": script, "scenario": scenario,
                                                  "bytes": byte_count, "completion_status": completion_status,
                                                  "responses": responses}),
                                text=True, capture_output=True, timeout=10, check=True)
        return json.loads(result.stdout)

    def test_opaque_response_is_not_reported_as_verified_body(self):
        report = self.execute("example.com", "single", "opaque", 999)
        result = report["result"]
        self.assertEqual((result["completed"], result["opaque_bodies"], result["verified_bodies"], result["body_bytes"]), (1, 1, 0, 0))
        self.assertEqual(report["reads"], 0)

    def test_http_error_and_wrong_download_size_never_count_as_completed(self):
        for scenario, size in (("bad_status", 1048576), ("success", 7)):
            report = self.execute("speed.cloudflare.com", "download", scenario, size)
            self.assertEqual(report["result"]["completed"], 0)
            self.assertEqual(report["result"]["verified_bodies"], 0)
            self.assertEqual(len(report["result"]["errors"]), 1)

    def test_success_waits_for_actual_body_resolution_and_exact_download_bytes(self):
        report = self.execute("speed.cloudflare.com", "download", "success", 1048576)
        self.assertTrue(report["bodyResolved"])
        self.assertEqual(report["reads"], 1)
        self.assertEqual(report["result"]["body_bytes"], 1048576)
        self.assertEqual(report["result"]["verified_bodies"], 1)
        self.assertEqual(report["result"]["completed"], 1)

    def test_bulk_profiles_reject_unverified_origins(self):
        for profile in ("upload", "download", "page_download", "bootstrap_download"):
            self.assertEqual(self.emitted_page("example.com", profile)[0], 400)

    def test_completion_save_rejection_never_displays_a_successful_recorded_trial(self):
        for status in (400, 500):
            report = self.execute("example.com", "single", "opaque", 0, status)
            self.assertEqual(report["title"], "Traffic lab failed")
            self.assertIn(f"Completion not saved: HTTP {status}", report["display"])

    def test_page_download_verifies_two_bodies_before_requesting_the_next(self):
        report = self.execute("speed.cloudflare.com", "page_download", "success", 0,
                              responses=[{"scenario": "success", "bytes": 8192},
                                         {"scenario": "success", "bytes": 1048576}])
        self.assertEqual([request["url"] for request in report["requests"]], [
            "https://speed.cloudflare.com/__down?bytes=8192&trial=testtrial&request=0",
            "https://speed.cloudflare.com/__down?bytes=1048576&trial=testtrial&request=1",
        ])
        self.assertEqual([request["resolvedBodies"] for request in report["requests"]], [0, 1])
        self.assertTrue(all(request["method"] == "GET" and request["mode"] == "cors"
                            for request in report["requests"]))
        self.assertEqual(report["bodySizes"], [8192, 1048576])
        self.assertEqual(report["reads"], 2)
        self.assertEqual((report["result"]["completed"], report["result"]["verified_bodies"],
                          report["result"]["body_bytes"], report["result"]["opaque_bodies"]),
                         (2, 2, 1056768, 0))
        self.assertEqual(report["result"]["errors"], [])

    def test_protocol_diagnostics_are_scoped_to_each_completed_resource(self):
        for unavailable in ({"missingTiming": True}, {"protocol": ""}):
            with self.subTest(unavailable=unavailable):
                report = self.execute("speed.cloudflare.com", "page_download", "success", 0,
                                      responses=[{"scenario": "success", "bytes": 8192, "protocol": "h3"},
                                                 {"scenario": "success", "bytes": 1048576, **unavailable}])
                self.assertEqual(report["result"]["resource_protocols"], ["h3", "unavailable"])
                self.assertEqual(report["result"]["body_bytes"], 1056768)
                self.assertNotIn("unrelated.invalid", json.dumps(report))

    def test_speed_small_workloads_use_verified_cors_objects_with_unique_request_urls(self):
        for profile, count in (("single", 1), ("browse", 8), ("interactive", 12),
                               ("idle", 2), ("burst", 8)):
            with self.subTest(profile=profile):
                report = self.execute("speed.cloudflare.com", profile, "success", 8192)
                self.assertEqual(report["result"]["verified_bodies"], count)
                self.assertEqual(report["result"]["body_bytes"], count * 8192)
                self.assertEqual(report["result"]["errors"], [])
                self.assertEqual([request["url"] for request in report["requests"]], [
                    f"https://speed.cloudflare.com/__down?bytes=8192&trial=testtrial&request={i}"
                    for i in range(count)
                ])

    def test_page_download_stops_after_unverified_first_object(self):
        for scenario, size in (("success", 8191), ("bad_status", 8192), ("opaque", 8192)):
            with self.subTest(scenario=scenario):
                report = self.execute("speed.cloudflare.com", "page_download", scenario, size)
                self.assertEqual(len(report["requests"]), 1)
                self.assertEqual((report["result"]["completed"], report["result"]["verified_bodies"],
                                  report["result"]["body_bytes"]), (0, 0, 0))
                self.assertEqual(len(report["result"]["errors"]), 1)
                self.assertEqual(report["reads"], int(scenario == "success"))

    def test_page_download_never_counts_an_incomplete_or_failed_second_object(self):
        for scenario, size in (("success", 1048575), ("bad_status", 1048576)):
            with self.subTest(scenario=scenario):
                report = self.execute("speed.cloudflare.com", "page_download", "success", 0,
                                      responses=[{"scenario": "success", "bytes": 8192},
                                                 {"scenario": scenario, "bytes": size}])
                self.assertEqual(len(report["requests"]), 2)
                self.assertEqual((report["result"]["completed"], report["result"]["verified_bodies"],
                                  report["result"]["body_bytes"]), (1, 1, 8192))
                self.assertEqual(len(report["result"]["errors"]), 1)

    def test_page_download_completion_save_errors_still_reject_success(self):
        for status in (400, 500):
            report = self.execute("speed.cloudflare.com", "page_download", "success", 0, status,
                                  responses=[{"scenario": "success", "bytes": 8192},
                                             {"scenario": "success", "bytes": 1048576}])
            self.assertEqual(report["result"]["body_bytes"], 1056768)
            self.assertEqual(report["title"], "Traffic lab failed")
            self.assertIn(f"Completion not saved: HTTP {status}", report["display"])

    def bootstrap_responses(self, post_sizes=(0, 0)):
        return [{"scenario": "success", "bytes": size}
                for size in (post_sizes[0], 8192, post_sizes[1], 4096, 1048576)]

    def test_bootstrap_download_executes_the_five_steps_after_each_body_completes(self):
        report = self.execute("speed.cloudflare.com", "bootstrap_download", "success", 0,
                              responses=self.bootstrap_responses())
        self.assertEqual([(request["method"], request["url"]) for request in report["requests"]], [
            ("POST", "https://speed.cloudflare.com/__up?trial=testtrial&request=0"),
            ("GET", "https://speed.cloudflare.com/__down?bytes=8192&trial=testtrial&request=1"),
            ("POST", "https://speed.cloudflare.com/__up?trial=testtrial&request=2"),
            ("GET", "https://speed.cloudflare.com/__down?bytes=4096&trial=testtrial&request=3"),
            ("GET", "https://speed.cloudflare.com/__down?bytes=1048576&trial=testtrial&request=4"),
        ])
        self.assertEqual([request["bodyLength"] for request in report["requests"]], [1536, 0, 1536, 0, 0])
        self.assertEqual([request["resolvedBodies"] for request in report["requests"]], list(range(5)))
        self.assertTrue(all(request["mode"] == "cors" for request in report["requests"]))
        self.assertTrue(all(request["bodyAllZero"] for request in report["requests"]
                            if request["method"] == "POST"))
        self.assertEqual(report["bodySizes"], [0, 8192, 0, 4096, 1048576])
        self.assertEqual(report["reads"], 5)
        self.assertEqual(report["sleeps"], [])
        result = report["result"]
        self.assertEqual((result["completed"], result["verified_bodies"], result["body_bytes"],
                          result["opaque_bodies"]), (5, 5, 1060864, 0))
        self.assertEqual(result["resource_protocols"], ["h2"] * 5)
        self.assertEqual(result["errors"], [])
        self.assertEqual(report["title"], "Traffic lab done testtrial")

    def test_bootstrap_post_response_sizes_are_recorded_without_upload_attestation(self):
        report = self.execute("speed.cloudflare.com", "bootstrap_download", "success", 0,
                              responses=self.bootstrap_responses(post_sizes=(7, 13)))
        self.assertEqual(report["result"]["completed"], 5)
        self.assertEqual(report["result"]["verified_bodies"], 5)
        self.assertEqual(report["result"]["body_bytes"], 1060864 + 7 + 13)
        self.assertEqual(report["result"]["errors"], [])

    def test_speed_upload_keeps_its_synthetic_body_and_uses_a_unique_request_url(self):
        report = self.execute("speed.cloudflare.com", "upload", "success", 0)
        self.assertEqual(len(report["requests"]), 1)
        request = report["requests"][0]
        self.assertEqual((request["method"], request["url"], request["bodyLength"]),
                         ("POST", "https://speed.cloudflare.com/__up?trial=testtrial&request=0", 1048576))
        self.assertTrue(request["bodyAllZero"])
        self.assertEqual((report["result"]["completed"], report["result"]["verified_bodies"]), (1, 1))

    def test_bootstrap_download_stops_after_any_failed_or_opaque_step(self):
        for scenario in ("bad_status", "opaque", "fetch_error", "body_error"):
            for index in range(5):
                with self.subTest(scenario=scenario, step=index):
                    responses = self.bootstrap_responses()
                    responses[index]["scenario"] = scenario
                    report = self.execute("speed.cloudflare.com", "bootstrap_download", "success", 0,
                                          responses=responses)
                    self.assertEqual(len(report["requests"]), index + 1)
                    result = report["result"]
                    self.assertEqual((result["completed"], result["verified_bodies"]), (index, index))
                    self.assertEqual(result["body_bytes"], sum(response["bytes"] for response in responses[:index]))
                    self.assertEqual(len(result["resource_protocols"]), index)
                    self.assertEqual(len(result["errors"]), 1)
                    self.assertEqual(report["title"], "Traffic lab failed")

    def test_bootstrap_download_stops_after_each_wrong_sized_get(self):
        for index in (1, 3, 4):
            for delta in (-1, 1):
                with self.subTest(step=index, delta=delta):
                    responses = self.bootstrap_responses()
                    responses[index]["bytes"] += delta
                    report = self.execute("speed.cloudflare.com", "bootstrap_download", "success", 0,
                                          responses=responses)
                    self.assertEqual(len(report["requests"]), index + 1)
                    result = report["result"]
                    self.assertEqual((result["completed"], result["verified_bodies"]), (index, index))
                    self.assertEqual(result["body_bytes"], sum(response["bytes"] for response in responses[:index]))
                    self.assertEqual(len(result["errors"]), 1)
                    self.assertIn("byte count mismatch", result["errors"][0])
                    self.assertEqual(report["title"], "Traffic lab failed")

    def test_bootstrap_completion_save_rejection_cannot_display_recorded_success(self):
        for status in (400, 500):
            report = self.execute("speed.cloudflare.com", "bootstrap_download", "success", 0, status,
                                  responses=self.bootstrap_responses())
            self.assertEqual(report["result"]["completed"], 5)
            self.assertEqual(report["title"], "Traffic lab failed")
            self.assertIn(f"Completion not saved: HTTP {status}", report["display"])


class PrivilegeTests(unittest.TestCase):
    def test_privilege_drop_order_without_changing_real_credentials(self):
        calls = []
        with mock.patch.object(relay.os, "geteuid", return_value=0), \
             mock.patch.dict(relay.os.environ, {"SUDO_UID": "501", "SUDO_GID": "20"}), \
             mock.patch.object(relay.os, "setgroups", side_effect=lambda value: calls.append(("groups", value))), \
             mock.patch.object(relay.os, "setgid", side_effect=lambda value: calls.append(("gid", value))), \
             mock.patch.object(relay.os, "setuid", side_effect=lambda value: calls.append(("uid", value))):
            relay.drop_bind_privilege(mock.Mock())
        self.assertEqual(calls, [("groups", []), ("gid", 20), ("uid", 501)])


class PortGraphTests(unittest.TestCase):
    def validate(self, **overrides):
        with contextlib.redirect_stderr(io.StringIO()):
            relay.validate_ports(arguments(**overrides), argparse.ArgumentParser())

    def test_listener_collisions_direct_backend_loops_and_invalid_ports_are_rejected(self):
        for field in ("observe_port", "normal_socks_port", "http_connect_port", "pac_port"):
            for upstream in ("upstream_socks_port", "normal_next_hop_port"):
                with self.subTest(field=field, upstream=upstream), self.assertRaises(SystemExit):
                    self.validate(**{upstream: getattr(arguments(), field)})
        for field in ("observe_port", "normal_socks_port", "proxy_socks_port", "upstream_socks_port",
                      "normal_next_hop_port", "http_connect_port", "pac_port"):
            for value in (0, -1, 65536):
                with self.subTest(field=field, value=value), self.assertRaises(SystemExit):
                    self.validate(**{field: value})
        with self.assertRaises(SystemExit):
            self.validate(observe_port=1081)
        with self.assertRaises(SystemExit):
            self.validate(upstream_socks_port=1080, normal_next_hop_port=58454)

    def test_default_internal_observer_and_pac_only_proxy_reference_are_permitted(self):
        self.validate()
        self.validate(normal_next_hop_port=58454)
        self.validate(upstream_socks_port=1080)
        self.validate(proxy_socks_port=1081)


class ShutdownTests(unittest.TestCase):
    def test_sigterm_closes_stalled_accepted_connections_without_waiting_for_deadline(self):
        reservations = [socket.socket() for _ in range(4)]
        for connection in reservations:
            connection.bind(("127.0.0.1", 0))
        ports = [connection.getsockname()[1] for connection in reservations]
        for connection in reservations:
            connection.close()
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, "-B", str(pathlib.Path(relay.__file__).resolve()),
                       "--host", "example.invalid", "--output", directory]
            for option, port in zip(("--pac-port", "--observe-port", "--normal-socks-port",
                                     "--http-connect-port"), ports):
                command.extend((option, str(port)))
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True)
            clients = []
            try:
                self.assertTrue(select.select([process.stdout], [], [], 5)[0], "relay did not start")
                self.assertTrue(json.loads(process.stdout.readline())["ready"])
                for port in ports[2:]:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                    clients.append(connection)
                # Observe the SOCKS method reply: the accepted handler is active
                # and is waiting for a CONNECT that this test never sends.
                clients[0].sendall(b"\x05\x01\x00")
                self.assertEqual(clients[0].recv(2), b"\x05\x00")
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                self.assertEqual(clients[0].recv(1), b"")
            finally:
                for connection in clients:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
