from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import WebSocket

if TYPE_CHECKING:
    from app.websocket_relay import WebSocketRelay


logger = logging.getLogger(__name__)


@dataclass
class ConsoleConnection:
    connection_id: str
    owner_id: str
    websocket: WebSocket


@dataclass
class SessionRoute:
    session_id: str
    device_id: str
    console_connection_id: str


class WebSocketManager:
    """Tiene in memoria solo le connessioni live dell'istanza backend."""

    def __init__(
        self,
        relay: "WebSocketRelay | None" = None,
        metrics=None,
        max_console_connections=6,
        max_connections=1000,
    ) -> None:
        self.device_connections: dict[str, WebSocket] = {}
        self._connecting_devices: set[str] = set()
        self._connecting_consoles: dict[str, str] = {}
        self.max_console_connections = max_console_connections
        self.max_connections = max_connections
        self.console_connections: dict[str, ConsoleConnection] = {}
        self.session_routes: dict[str, SessionRoute] = {}
        self.relay = relay
        self.metrics = metrics
        self.remote_devices: set[str] = set()

    def has_connection_capacity(self):
        return (
            len(self.device_connections)
            + len(self._connecting_devices)
            + len(self.console_connections)
            + len(self._connecting_consoles)
        ) < self.max_connections

    def reserve_console(self, connection_id, owner_id):
        # No await between checking and reserving: atomic in the single ASGI worker.
        owned = sum(c.owner_id == owner_id for c in self.console_connections.values())
        owned += sum(owner == owner_id for owner in self._connecting_consoles.values())
        if owned >= self.max_console_connections or not self.has_connection_capacity():
            return False
        self._connecting_consoles[connection_id] = owner_id
        return True

    def release_console_reservation(self, connection_id):
        self._connecting_consoles.pop(connection_id, None)

    async def connect_device(self, device_id: str, websocket: WebSocket) -> bool:
        # Reserve the handshake without advertising the device online until accepted.
        if (
            device_id in self.device_connections
            or device_id in self._connecting_devices
            or not self.has_connection_capacity()
        ):
            return False
        self._connecting_devices.add(device_id)
        try:
            await websocket.accept()
            self.device_connections[device_id] = websocket
        finally:
            self._connecting_devices.discard(device_id)
        logger.info(f"Device connected: {device_id}")
        # Broadcast device connection event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "device_connected",
                    "device_id": device_id,
                }
            )
        return True

    def disconnect_device(self, device_id: str) -> list[str]:
        logger.info(f"Device disconnected: {device_id}")
        self.device_connections.pop(device_id, None)
        ended = [
            session_id
            for session_id, route in self.session_routes.items()
            if route.device_id == device_id
        ]
        for session_id in ended:
            self.unbind_session(session_id)
        logger.debug(f"Sessions ended due to device disconnect: {ended}")
        # Broadcast device disconnection event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "device_disconnected",
                    "device_id": device_id,
                }
            )
        return ended

    async def disconnect_device_if_present(
        self, device_id: str, code: int = 1000
    ) -> None:
        websocket = self.device_connections.get(device_id)
        self.disconnect_device(device_id)
        if websocket is not None:
            with contextlib.suppress(Exception):
                await websocket.close(code=code)

    def is_device_online(self, device_id: str) -> bool:
        return device_id in self.device_connections or (
            self.relay is not None
            and self.relay.healthy
            and device_id in self.remote_devices
        )

    async def connect_console(
        self, connection_id: str, owner_id: str, websocket: WebSocket
    ) -> None:
        logger.info(f"Console connected: {connection_id} for user {owner_id}")
        self.console_connections[connection_id] = ConsoleConnection(
            connection_id, owner_id, websocket
        )
        self.release_console_reservation(connection_id)
        # Broadcast console connection event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "console_connected",
                    "connection_id": connection_id,
                    "owner_id": owner_id,
                }
            )

    def disconnect_console(self, connection_id: str) -> list[str]:
        logger.info(f"Console disconnected: {connection_id}")
        self.console_connections.pop(connection_id, None)
        ended = [
            session_id
            for session_id, route in self.session_routes.items()
            if route.console_connection_id == connection_id
        ]
        for session_id in ended:
            self.unbind_session(session_id)
        logger.debug(f"Sessions ended due to console disconnect: {ended}")
        # Broadcast console disconnection event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "console_disconnected",
                    "connection_id": connection_id,
                }
            )
        return ended

    def bind_session(
        self, session_id: str, device_id: str, console_connection_id: str
    ) -> None:
        if session_id not in self.session_routes and self.metrics:
            self.metrics.record_session_event("opened")
        self.session_routes[session_id] = SessionRoute(
            session_id, device_id, console_connection_id
        )
        # Broadcast session bind event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "session_bound",
                    "session_id": session_id,
                    "device_id": device_id,
                    "console_connection_id": console_connection_id,
                }
            )

    def unbind_session(self, session_id: str) -> None:
        removed = self.session_routes.pop(session_id, None)
        if removed and self.metrics:
            self.metrics.record_session_event("closed")
        # Broadcast session unbind event to other servers
        if self.relay:
            self.relay.broadcast(
                {
                    "type": "session_unbound",
                    "session_id": session_id,
                }
            )

    def get_route(self, session_id: str) -> SessionRoute | None:
        return self.session_routes.get(session_id)

    async def send_to_device(self, device_id: str, message: dict) -> bool:
        websocket = self.device_connections.get(device_id)
        if websocket is None:
            logger.warning(f"Cannot send to device {device_id}: not connected")
            # Try to send via relay if available
            if self.relay:
                return await self.relay.send("device_message", device_id, message)
            return False
        try:
            await websocket.send_json(message)
            logger.debug(
                f"Sent to device {device_id}: {message.get('type', 'unknown')}"
            )
            return True
        except Exception as error:
            logger.error(
                "Failed to send to device %s",
                device_id,
                extra={"extra_fields": {"error_type": type(error).__name__}},
            )
            return False

    async def send_to_console(self, connection_id: str, message: dict | bytes) -> bool:
        connection = self.console_connections.get(connection_id)
        if connection is None:
            logger.warning(f"Cannot send to console {connection_id}: not connected")
            # Try to send via relay if available
            if self.relay:
                return await self.relay.send("console_message", connection_id, message)
            return False
        try:
            if isinstance(message, bytes):
                await connection.websocket.send_bytes(message)
            else:
                await connection.websocket.send_json(message)
            logger.debug("Sent message to console %s", connection_id)
            return True
        except Exception as error:
            logger.error(
                "Failed to send to console %s",
                connection_id,
                extra={"extra_fields": {"error_type": type(error).__name__}},
            )
            return False

    async def forward_to_console_by_session(
        self, session_id: str, message: dict | bytes
    ) -> bool:
        route = self.session_routes.get(session_id)
        if route is None:
            logger.warning(
                f"Cannot forward to console: no route for session {session_id}"
            )
            return False
        return await self.send_to_console(route.console_connection_id, message)

    async def forward_to_device_by_session(
        self, session_id: str, message: dict
    ) -> bool:
        route = self.session_routes.get(session_id)
        if route is None:
            logger.warning(
                f"Cannot forward to device: no route for session {session_id}"
            )
            return False
        message_type = message.get("type", "unknown")
        try:
            result = await self.send_to_device(route.device_id, message)
            if result:
                logger.debug(
                    f"Forwarded {message_type} for session {session_id} to device"
                )
            return result
        except Exception as error:
            logger.error(
                "Failed to forward %s for session %s",
                message_type,
                session_id,
                extra={"extra_fields": {"error_type": type(error).__name__}},
            )
            return False

    async def handle_relay_message(self, message: dict) -> bool | None:
        """Apply peer events without rebroadcasting; acknowledge only local delivery."""
        kind = message.get("type")
        if kind == "device_connected":
            self.remote_devices.add(message["device_id"])
        elif kind == "device_disconnected":
            self.remote_devices.discard(message["device_id"])
        elif kind == "session_bound":
            self.session_routes[message["session_id"]] = SessionRoute(
                message["session_id"],
                message["device_id"],
                message["console_connection_id"],
            )
        elif kind == "session_unbound":
            self.session_routes.pop(message["session_id"], None)
        elif kind == "snapshot_request":
            for device_id in self.device_connections:
                self.relay.broadcast(
                    {"type": "device_connected", "device_id": device_id}
                )
            for route in self.session_routes.values():
                self.relay.broadcast(
                    {
                        "type": "session_bound",
                        "session_id": route.session_id,
                        "device_id": route.device_id,
                        "console_connection_id": route.console_connection_id,
                    }
                )
        elif (
            kind == "device_message"
            and message["destination"] in self.device_connections
        ):
            return await self.send_to_device(message["destination"], message["payload"])
        elif (
            kind == "console_message"
            and message["destination"] in self.console_connections
        ):
            return await self.send_to_console(
                message["destination"], message["payload"]
            )
        return None
