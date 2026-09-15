"""Experimental Redis Pub/Sub transport with acknowledgements and bounded queues.

Pub/Sub is transient: callers receive failure on missing peers/timeouts, never an
implicit delivery guarantee. Multi-instance production lifecycle is still gated.

Questo programma è software libera: puoi ridistribuirlo e/o modificarlo
sotto i termini della GNU General Public License come pubblicata dalla
Free Software Foundation, versione 3 della Licenza o (a propria scelta)
qualsiasi versione successiva.

Questo programma è distribuito nella speranza che sia utile, ma SENZA
ALCUNA GARANZIA; senza neppure la garanzia implicita di COMMERCIABILITÀ
o IDONEITÀ PER UNO SCOPO PARTICOLARE. Vedere la GNU General Public License
per dettagli.

Dovresti aver ricevuto una copia della GNU General Public License
insieme a questo programma. Se non è così, vedere <https://www.gnu.org/licenses/>.
"""

import asyncio
import base64
import contextlib
import json
import logging
import uuid

import redis.asyncio as redis
from opentelemetry import context, propagate

from app.correlation import correlation_id_context, get_request_id

logger = logging.getLogger(__name__)


class WebSocketRelay:
    def __init__(
        self, redis_url, *, channel="mydesk:ws:v1", timeout=2.0, queue_size=16
    ):
        self.instance_id = uuid.uuid4().hex
        self.channel = channel
        self.timeout = timeout
        self.client = redis.from_url(
            redis_url, socket_connect_timeout=timeout, socket_timeout=timeout
        )
        self.pubsub = None
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.pending = {}
        self.tasks = []
        self.healthy = False
        self.handler = None

    async def start(self, handler):
        self.handler = handler
        try:
            await self.client.ping()
            self.pubsub = self.client.pubsub()
            await self.pubsub.subscribe(self.channel)
            # Wait for subscription acknowledgement before advertising readiness.
            async with asyncio.timeout(self.timeout):
                while True:
                    message = await self.pubsub.get_message(timeout=self.timeout)
                    if message and message["type"] == "subscribe":
                        break
            self.healthy = True
            self.tasks = [
                asyncio.create_task(self._read()),
                asyncio.create_task(self._write()),
            ]
        except Exception:
            await self.close()
            raise

    def broadcast(self, message):
        return self._enqueue(message, None)

    def _enqueue(self, message, request):
        if not self.healthy:
            return False
        carrier = {}
        propagate.inject(carrier)
        packet = {
            "origin": self.instance_id,
            "message": message,
            "request": request,
            "request_id": get_request_id(),
            "trace": carrier,
        }
        try:
            self.queue.put_nowait(packet)
            return True
        except asyncio.QueueFull:
            logger.warning("WebSocket relay queue full")
            self._failed()
            return False

    async def send(self, kind, destination, payload):
        request = uuid.uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.pending[request] = future
        binary = isinstance(payload, bytes)
        message = {
            "type": kind,
            "destination": destination,
            "binary": binary,
            "payload": base64.b64encode(payload).decode("ascii") if binary else payload,
        }
        try:
            if not self._enqueue(message, request):
                return False
            return await asyncio.wait_for(future, self.timeout)
        except TimeoutError:
            return False
        finally:
            self.pending.pop(request, None)

    async def _write(self):
        try:
            while True:
                packet = await self.queue.get()
                try:
                    await self.client.publish(self.channel, json.dumps(packet))
                finally:
                    self.queue.task_done()
        except Exception:
            self._failed()

    async def _read(self):
        try:
            while True:
                raw = await self.pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1
                )
                if raw is None:
                    continue
                try:
                    packet = json.loads(raw["data"])
                    if packet.get("origin") == self.instance_id:
                        continue
                    if packet.get("reply_to") == self.instance_id:
                        future = self.pending.get(packet.get("request"))
                        if future and not future.done():
                            future.set_result(packet.get("ok") is True)
                        continue
                    if "reply_to" in packet:
                        continue
                    message = packet["message"]
                    if message.get("binary"):
                        message["payload"] = base64.b64decode(
                            message["payload"], validate=True
                        )
                    token = context.attach(propagate.extract(packet.get("trace", {})))
                    try:
                        with correlation_id_context(packet.get("request_id")):
                            handled = await asyncio.wait_for(
                                self.handler(message), self.timeout
                            )
                    finally:
                        context.detach(token)
                    if packet.get("request") and handled is not None:
                        await self.client.publish(
                            self.channel,
                            json.dumps(
                                {
                                    "origin": self.instance_id,
                                    "reply_to": packet["origin"],
                                    "request": packet["request"],
                                    "ok": handled,
                                }
                            ),
                        )
                except (ValueError, KeyError, TypeError):
                    logger.warning("Invalid relay packet ignored")
        except Exception:
            self._failed()

    def _failed(self):
        self.healthy = False
        logger.error("WebSocket relay disconnected; readiness is unavailable")
        for future in self.pending.values():
            if not future.done():
                future.set_result(False)

    async def close(self):
        self.healthy = False
        for future in self.pending.values():
            if not future.done():
                future.set_result(False)
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()
        if self.pubsub is not None:
            with contextlib.suppress(redis.RedisError):
                await self.pubsub.aclose()
        await self.client.aclose()
