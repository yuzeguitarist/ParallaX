"""Actual loopback byte/half-close/timing/backpressure and shutdown regressions."""

import asyncio
import contextlib
import io
import json
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import types
import unittest
from unittest import mock

import relay
import shaper


class ShaperTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.shapers = []
        self.clients = []
        self.handlers = set()

    async def asyncTearDown(self):
        for instance in self.shapers:
            await instance.close()
            self.assertFalse(instance.active)
            self.assertFalse(instance.writers)
        await shaper.close_streams(*self.clients)
        for task in list(self.handlers):
            task.cancel()
        await asyncio.gather(*self.handlers, return_exceptions=True)
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def origin(self, callback):
        async def tracked(reader, writer):
            task = asyncio.current_task()
            self.handlers.add(task)
            try:
                await callback(reader, writer)
            finally:
                await shaper.close_streams(writer)
                self.handlers.discard(task)
        server = await asyncio.start_server(tracked, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def connect(self, origin_port, delay_ms):
        instance = shaper.DelayShaper(0, origin_port, delay_ms)
        self.shapers.append(instance)
        port = await instance.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.clients.append(writer)
        return instance, reader, writer

    async def test_zero_and_delayed_bidirectional_bytes_preserve_half_close_and_late_response(self):
        payload = bytes(range(256)) * 1024
        response = payload[::-1]
        for delay_ms in (0, 25):
            observed = asyncio.get_running_loop().create_future()
            async def origin(reader, writer):
                # Reverse traffic must progress before this peer sees input/EOF.
                writer.write(b"banner")
                await writer.drain()
                data = await reader.read()
                observed.set_result(data)
                await asyncio.sleep(0.005)
                writer.write(response)
                await writer.drain()
                writer.write_eof()
            port = await self.origin(origin)
            _, reader, writer = await self.connect(port, delay_ms)
            self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 1), b"banner")
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), response)
            self.assertEqual(await observed, payload)

    async def test_http_gate_and_real_shim_preserve_allowlist_and_half_closed_exchange(self):
        payload = bytes(range(256)) * 1024
        response = payload[::-1] * 4
        observed = asyncio.get_running_loop().create_future()

        async def origin(reader, writer):
            observed.set_result(await reader.read())
            writer.write(response)
            await writer.drain()
            writer.write_eof()

        origin_port = await self.origin(origin)
        instance = shaper.DelayShaper(0, origin_port, 25)
        self.shapers.append(instance)
        shim_port = await instance.start()
        args = types.SimpleNamespace(host="example.com", upstream_socks_port=None,
                                     normal_next_hop_port=shim_port, observe_port=origin_port)

        async def gate(reader, writer):
            await relay.handle_http_connect(reader, writer, args)

        gate_port = await self.origin(gate)
        with mock.patch.object(relay, "resolve_allowed_origin",
                               mock.AsyncMock(return_value=["203.0.113.8"])) as resolve, \
             contextlib.redirect_stdout(io.StringIO()):
            rejected_reader, rejected_writer = await asyncio.open_connection("127.0.0.1", gate_port)
            self.clients.append(rejected_writer)
            rejected_writer.write(b"CONNECT 198.51.100.9:443 HTTP/1.1\r\n\r\n")
            await rejected_writer.drain()
            self.assertIn(b"403", await asyncio.wait_for(rejected_reader.read(), 1))
            self.assertFalse(observed.done(), "rejected authority must not reach the fixed upstream")
            self.assertFalse(instance.active)

            reader, writer = await asyncio.open_connection("127.0.0.1", gate_port)
            self.clients.append(writer)
            writer.write(b"CONNECT 203.0.113.8:443 HTTP/1.1\r\n\r\n")
            await writer.drain()
            self.assertIn(b"200", await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 1))
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), response)
            self.assertEqual(await observed, payload)
            self.assertEqual(resolve.await_args_list,
                             [mock.call("example.com"), mock.call("example.com")])

    async def test_first_byte_is_delayed_but_ready_chunks_share_the_pipeline(self):
        payload = b"p" * (shaper.CHUNK_BYTES * 8)
        ready = asyncio.Event()
        async def origin(_reader, writer):
            await ready.wait()
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
        port = await self.origin(origin)
        _, reader, writer = await self.connect(port, 50)
        writer.write_eof()
        loop = asyncio.get_running_loop()
        started = loop.time()
        ready.set()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(1), 1), b"p")
        first = loop.time() - started
        self.assertGreaterEqual(first, 0.048)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), payload[1:])
        elapsed = loop.time() - started
        # Eight serial 50ms sleeps take >=400ms. A 200ms upper bound allows
        # scheduling slack without accepting that broken N*delay behavior.
        self.assertLess(elapsed, 0.2, (first, elapsed))

    async def test_queue_is_bounded_and_full_queue_stops_further_reads_until_drain(self):
        queues = []
        full = asyncio.Event()
        original_queue = asyncio.Queue
        original_read = asyncio.StreamReader.read
        read_sizes = {}
        class ObservedQueue(original_queue):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                queues.append(self)
            async def put(self, item):
                await super().put(item)
                if self.qsize() == shaper.QUEUE_CHUNKS:
                    full.set()
        async def counted_read(reader, amount=-1):
            data = await original_read(reader, amount)
            read_sizes[reader] = read_sizes.get(reader, 0) + len(data)
            return data
        async def origin(_reader, _writer):
            await asyncio.Future()
        port = await self.origin(origin)
        with mock.patch.object(shaper.asyncio, "Queue", ObservedQueue), \
             mock.patch.object(asyncio.StreamReader, "read", counted_read):
            instance, _reader, writer = await self.connect(port, 200)
            writer.write(b"q" * shaper.CHUNK_BYTES * 32)
            await writer.drain()
            await asyncio.wait_for(full.wait(), 0.15)
            for _ in range(5):
                await asyncio.sleep(0)
            self.assertEqual(max(queue.qsize() for queue in queues), shaper.QUEUE_CHUNKS)
            self.assertTrue(all(queue.maxsize == shaper.QUEUE_CHUNKS for queue in queues))
            # Eight queued, one writer-owned and at most one producer-owned
            # chunk. The producer must await queue capacity before reading more.
            self.assertLessEqual(max(read_sizes.values()), (shaper.QUEUE_CHUNKS + 2) * shaper.CHUNK_BYTES)
            await instance.close()
            self.assertFalse(instance.active)
            self.assertFalse(instance.writers)

    async def test_idle_io_and_refused_connect_close_both_sides(self):
        async def origin(_reader, _writer):
            await asyncio.Future()
        port = await self.origin(origin)
        with mock.patch.object(shaper, "IO_TIMEOUT", 0.03), mock.patch("builtins.print") as logged:
            _, reader, _writer = await self.connect(port, 0)
            self.assertEqual(await asyncio.wait_for(reader.read(), 0.5), b"")
            self.assertEqual(json.loads(logged.call_args.args[0]), {
                "event": "shaper_connection_failed", "phase": "forward", "error_type": "TimeoutError"})
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        unused = reservation.getsockname()[1]
        reservation.close()
        with mock.patch("builtins.print") as logged:
            _, reader, _writer = await self.connect(unused, 0)
            self.assertEqual(await asyncio.wait_for(reader.read(), 0.5), b"")
            self.assertEqual(json.loads(logged.call_args.args[0]), {
                "event": "shaper_connection_failed", "phase": "connect",
                "error_type": "ConnectionRefusedError"})

    async def test_close_aborts_a_transport_that_cannot_finish_close(self):
        writer = mock.Mock()
        async def blocked():
            await asyncio.Future()
        writer.wait_closed = mock.AsyncMock(side_effect=blocked)
        with mock.patch.object(shaper, "CLOSE_TIMEOUT", 0.01):
            await asyncio.wait_for(shaper.close_streams(writer), 0.2)
        writer.close.assert_called_once()
        writer.transport.abort.assert_called_once()

    async def test_stalled_drain_is_bounded_and_cancels_its_reader_task(self):
        connected = asyncio.get_running_loop().create_future()
        async def origin(reader, writer):
            connected.set_result((reader, writer))
            await asyncio.Future()
        port = await self.origin(origin)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.clients.append(writer)
        origin_reader, origin_writer = await connected
        writer.write(b"actual loopback bytes")
        await writer.drain()
        async def blocked():
            await asyncio.Future()
        baseline = set(asyncio.all_tasks())
        with mock.patch.object(origin_writer, "drain", mock.AsyncMock(side_effect=blocked)) as drain, \
             mock.patch.object(shaper, "IO_TIMEOUT", 0.02):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(shaper.delayed_direction(origin_reader, origin_writer, 0), 0.3)
            drain.assert_awaited_once()
        self.assertFalse(set(asyncio.all_tasks()) - baseline, "direction children must be reaped")
        self.assertEqual(await asyncio.wait_for(reader.readexactly(21), 0.2), b"actual loopback bytes")


class CliTests(unittest.TestCase):
    def test_ports_delay_and_direct_loop_are_validated_without_binding(self):
        base = ["--listen-port", "58454", "--upstream-port", "58444", "--delay-ms", "50"]
        self.assertEqual(shaper.parse_args(base).delay_ms, 50)
        for option, value in (("--listen-port", "0"), ("--listen-port", "65536"),
                              ("--upstream-port", "-1"), ("--upstream-port", "58454"),
                              ("--delay-ms", "-1"), ("--delay-ms", "nan"),
                              ("--delay-ms", "inf"), ("--delay-ms", "60001")):
            argv = base.copy()
            argv[argv.index(option) + 1] = value
            with self.subTest(option=option, value=value), contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit):
                shaper.parse_args(argv)

    def test_real_process_sigterm_closes_accepted_streams_and_releases_listener(self):
        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen()
        upstream.settimeout(2)
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        reservation.close()
        process = subprocess.Popen([
            sys.executable, "-B", str(Path(shaper.__file__).resolve()),
            "--listen-port", str(port), "--upstream-port", str(upstream.getsockname()[1]),
            "--delay-ms", "150",
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        client, accepted = None, None
        try:
            self.assertTrue(select.select([process.stdout], [], [], 3)[0], "shaper did not start")
            ready = json.loads(process.stdout.readline())
            self.assertTrue(ready["ready"])
            self.assertEqual(ready["pid"], process.pid)
            self.assertEqual(ready["listen_host"], "127.0.0.1")
            self.assertEqual(ready["queued_bytes_per_direction"], shaper.CHUNK_BYTES * shaper.QUEUE_CHUNKS)
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            accepted, _ = upstream.accept()
            accepted.settimeout(2)
            payload = b"synthetic data"
            client.sendall(payload)
            self.assertEqual(accepted.recv(len(payload)), payload)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stdout + stderr)
            self.assertEqual(client.recv(1), b"")
            self.assertEqual(accepted.recv(1), b"")
            with socket.socket() as rebound:
                # TIME_WAIT is legitimate; an extant listener would still
                # reject this bind because SO_REUSEPORT is deliberately absent.
                rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rebound.bind(("127.0.0.1", port))
        finally:
            for stream in (client, accepted, upstream):
                if stream is not None:
                    stream.close()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
