"""Real Redis Pub/Sub tests: two peers, binary frames, delivery failure and context."""

import asyncio
import os
import shutil
import subprocess
import time
import uuid
from unittest.mock import AsyncMock

import pytest
import redis

from app.correlation import correlation_id_context, get_request_id
from app.websocket_manager import WebSocketManager
from app.websocket_relay import WebSocketRelay


@pytest.fixture
def redis_url(tmp_path):
    configured = os.environ.get("MYDESK_TEST_REDIS_URL")
    if configured:
        yield configured
        return
    executable = shutil.which("redis-server")
    if not executable:
        pytest.skip("Set MYDESK_TEST_REDIS_URL or install redis-server")
    socket = tmp_path / "redis.sock"
    process = subprocess.Popen(
        [
            executable,
            "--port",
            "0",
            "--unixsocket",
            str(socket),
            "--save",
            "",
            "--appendonly",
            "no",
            "--dir",
            str(tmp_path),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"unix://{socket}"
    client = redis.from_url(url)
    try:
        for _ in range(100):
            try:
                if client.ping():
                    break
            except redis.ConnectionError:
                time.sleep(0.02)
        else:
            pytest.fail("Disposable Redis did not become ready")
        yield url
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=5)


def test_two_peers_relay_binary_and_json_without_echo_and_preserve_correlation(
    redis_url,
):
    async def run():
        channel = "mydesk:test:" + uuid.uuid4().hex
        first, second = [
            WebSocketRelay(redis_url, channel=channel, timeout=0.2) for _ in range(2)
        ]
        device_manager = WebSocketManager(relay=first)
        console_manager = WebSocketManager(relay=second)
        seen_context = []

        async def receive_at_device(message):
            seen_context.append(get_request_id())
            return await device_manager.handle_relay_message(message)

        await first.start(receive_at_device)
        await second.start(console_manager.handle_relay_message)
        device, console = AsyncMock(), AsyncMock()
        try:
            assert await device_manager.connect_device("device", device)
            await console_manager.connect_console("console", "owner", console)
            with correlation_id_context("relay-request"):
                console_manager.bind_session("session", "device", "console")
                assert await console_manager.send_to_device(
                    "device", {"type": "session_start"}
                )
            device.send_json.assert_awaited_once_with({"type": "session_start"})
            assert "relay-request" in seen_context
            assert device_manager.get_route("session") is not None
            frame = b"\x00\xff\x80jpeg\x00"
            assert await device_manager.forward_to_console_by_session("session", frame)
            console.send_bytes.assert_awaited_once_with(frame)
            console.send_json.assert_not_awaited()
            # No node owns this connection: publishing alone must not report delivery.
            assert not await console_manager.send_to_device("missing", {"type": "ping"})
            assert not second.pending
            assert first.queue.empty() and second.queue.empty()
        finally:
            await first.close()
            await second.close()
        assert not first.tasks and not second.tasks

    asyncio.run(run())


def test_relay_reports_failure_for_closed_peer_and_full_queue(redis_url):
    async def run():
        relay = WebSocketRelay(
            redis_url, channel="mydesk:test:" + uuid.uuid4().hex, queue_size=1
        )
        assert not await relay.send("device_message", "missing", {})
        # A stopped/overloaded transport must stop accepting messages and fail readiness.
        relay.healthy = True
        assert relay.broadcast({"type": "one"})
        assert not relay.broadcast({"type": "two"})
        assert not relay.healthy
        await relay.close()

    asyncio.run(run())
