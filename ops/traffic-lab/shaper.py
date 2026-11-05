#!/usr/bin/env python3
"""Loopback-only fixed additional byte-stream delay, not a TCP RTT simulator.

Both directions independently timestamp chunks when read and forward them in
FIFO order when due. Queue bounds exclude asyncio/OS socket buffers. This tool
does not inspect bytes, select destinations from traffic, or alter networking.
"""

import argparse
import asyncio
import datetime
import json
import math
import os
import signal


CHUNK_BYTES = 16384
QUEUE_CHUNKS = 8
CONNECT_TIMEOUT = 5
IO_TIMEOUT = 90
CLOSE_TIMEOUT = 1
SHUTDOWN_TIMEOUT = 3
MAX_DELAY_MS = 60000


async def close_streams(*writers):
    for writer in writers:
        writer.close()
    try:
        await asyncio.wait_for(asyncio.gather(
            *(writer.wait_closed() for writer in writers), return_exceptions=True,
        ), CLOSE_TIMEOUT)
    except asyncio.TimeoutError:
        for writer in writers:
            writer.transport.abort()


async def delayed_direction(reader, writer, delay):
    queue = asyncio.Queue(maxsize=QUEUE_CHUNKS)
    loop = asyncio.get_running_loop()

    async def read_chunks():
        while True:
            data = await asyncio.wait_for(reader.read(CHUNK_BYTES), IO_TIMEOUT)
            item = (loop.time() + delay, data) if data else None
            await asyncio.wait_for(queue.put(item), IO_TIMEOUT)
            if item is None:
                return

    async def write_chunks():
        while True:
            item = await asyncio.wait_for(queue.get(), IO_TIMEOUT)
            if item is None:
                # FIFO ensures every earlier byte has drained before the FIN.
                if not writer.can_write_eof():
                    raise OSError("loopback transport does not support half-close")
                writer.write_eof()
                await asyncio.wait_for(writer.drain(), IO_TIMEOUT)
                return
            due, data = item
            await asyncio.sleep(max(0, due - loop.time()))
            writer.write(data)
            await asyncio.wait_for(writer.drain(), IO_TIMEOUT)

    tasks = [asyncio.create_task(read_chunks()), asyncio.create_task(write_chunks())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class DelayShaper:
    def __init__(self, listen_port, upstream_port, delay_ms):
        self.listen_port = listen_port
        self.upstream_port = upstream_port
        self.delay = delay_ms / 1000
        self.server = None
        self.active = set()
        self.writers = set()
        self.stopping = False

    async def start(self):
        self.server = await asyncio.start_server(
            self.accept, "127.0.0.1", self.listen_port, limit=CHUNK_BYTES,
        )
        return self.server.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        if self.stopping:
            writer.close()
            writer.transport.abort()
            return
        self.writers.add(writer)
        task = asyncio.create_task(self.handle(reader, writer))
        self.active.add(task)
        task.add_done_callback(self.active.discard)

    async def handle(self, reader, writer):
        upstream = None
        directions = []
        try:
            if self.stopping:
                return
            upstream_reader, upstream = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.upstream_port, limit=CHUNK_BYTES),
                CONNECT_TIMEOUT,
            )
            self.writers.add(upstream)
            directions = [
                asyncio.create_task(delayed_direction(reader, upstream, self.delay)),
                asyncio.create_task(delayed_direction(upstream_reader, writer, self.delay)),
            ]
            # One clean EOF completes only its direction; the reverse may reply
            # after seeing that FIN, and retains its independent I/O backstop.
            await asyncio.gather(*directions)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for task in directions:
                task.cancel()
            await asyncio.gather(*directions, return_exceptions=True)
            owned = (writer, upstream) if upstream is not None else (writer,)
            await close_streams(*owned)
            self.writers.difference_update(owned)

    async def close(self):
        self.stopping = True
        if self.server is None:
            return
        self.server.close()
        for writer in list(self.writers):
            writer.close()
        tasks = list(self.active)
        for task in tasks:
            task.cancel()
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=SHUTDOWN_TIMEOUT)
            if pending:
                for writer in list(self.writers):
                    writer.transport.abort()
                for task in pending:
                    task.cancel()
                _, pending = await asyncio.wait(pending, timeout=CLOSE_TIMEOUT)
                if pending:
                    raise RuntimeError("shaper handlers did not stop within the shutdown bound")
        self.active.difference_update(tasks)
        # A handler cancelled before its first poll never enters its finally.
        await close_streams(*self.writers)
        self.writers.clear()
        await asyncio.wait_for(self.server.wait_closed(), CLOSE_TIMEOUT)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--delay-ms", type=float, required=True)
    args = parser.parse_args(argv)
    if not all(1 <= port <= 65535 for port in (args.listen_port, args.upstream_port)):
        parser.error("ports must be in 1..65535")
    if args.listen_port == args.upstream_port:
        parser.error("listen and upstream ports must differ (direct self-loop)")
    if not math.isfinite(args.delay_ms) or not 0 <= args.delay_ms <= MAX_DELAY_MS:
        parser.error(f"delay-ms must be finite and in 0..{MAX_DELAY_MS}")
    return args


async def serve(args):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    shaper = DelayShaper(args.listen_port, args.upstream_port, args.delay_ms)
    try:
        await shaper.start()
        print(json.dumps({
            "ready": True, "pid": os.getpid(),
            "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "listen_host": "127.0.0.1", "listen_port": args.listen_port,
            "upstream_host": "127.0.0.1", "upstream_port": args.upstream_port,
            "additional_delay_ms_per_direction": args.delay_ms,
            "chunk_bytes": CHUNK_BYTES, "queued_chunks_per_direction": QUEUE_CHUNKS,
            "queued_bytes_per_direction": CHUNK_BYTES * QUEUE_CHUNKS,
            "max_application_chunk_bytes_per_direction": CHUNK_BYTES * (QUEUE_CHUNKS + 2),
            "connect_timeout_seconds": CONNECT_TIMEOUT, "io_timeout_seconds": IO_TIMEOUT,
        }), flush=True)
        await stop.wait()
    finally:
        await shaper.close()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


if __name__ == "__main__":
    asyncio.run(serve(parse_args()))
