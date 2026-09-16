from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.authentication import authenticate_user
from app.auth_service import AuthService
from app.device_auth import DeviceChallenges, verify_proof
from app.models import Device, RemoteSession, User
from app.routes.devices import serialize_device
from app.screen_frames import parse_screen_frame_header
from app.security import generate_id, hash_secret
from app.timeutils import utc_now
from app.rate_limiting import enforce_limit
from app.websocket_validation import parse_control
from app.websocket_limits import (
    FrameBudget,
    WebSocketRateLimiter,
    allow_control,
    allow_upgrade,
    reject_connection,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])
AUTH_RECHECK_SECONDS = 1


def _bearer_token(websocket: WebSocket) -> str | None:
    header = websocket.headers.get("authorization")
    if header and header.lower().startswith("bearer "):
        return header.split(" ", 1)[1]
    for protocol in websocket.scope.get("subprotocols", []):
        if protocol.startswith("bearer."):
            return protocol.removeprefix("bearer.")
    return None


def _db(websocket: WebSocket) -> Session:
    return websocket.app.state.SessionLocal()


async def _end_sessions(
    db: Session,
    websocket: WebSocket,
    session_ids: list[str],
    reason: str,
    *,
    notify_device: bool = True,
    notify_console: bool = True,
) -> None:
    manager = websocket.app.state.ws_manager
    now = utc_now()
    notifications = []
    for session_id in session_ids:
        session = db.get(RemoteSession, session_id)
        if session is None or session.status != "in_session":
            continue
        session.status = "ended"
        session.ended_at = now
        session.end_reason = reason
        device = db.get(Device, session.device_id)
        if device and device.revoked_at is None:
            device.status = (
                "online" if manager.is_device_online(device.id) else "offline"
            )
        write_audit(
            db,
            "session_closed",
            owner_id=session.owner_id,
            device_id=session.device_id,
            session_id=session.id,
            payload={"reason": reason},
        )
        notifications.append(
            (
                session.device_id,
                session.console_connection_id,
                {
                    "type": "session_end",
                    "sessionId": session.id,
                    "reason": reason,
                },
            )
        )
    # Persist the entire cleanup and release DB locks before a peer can block I/O.
    db.commit()
    for session_id in session_ids:
        if manager.get_route(session_id) is not None:
            manager.unbind_session(session_id)
    for device_id, connection_id, message in notifications:
        if notify_device:
            await manager.send_to_device(device_id, message)
        if notify_console:
            await manager.send_to_console(connection_id, message)


@router.websocket("/device/ws")
async def device_ws(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin and origin not in websocket.app.state.settings.allowed_origins_list:
        await websocket.close(code=4403)
        return
    if not await allow_upgrade(websocket):
        return
    # Release the DB connection even when authentication or cleanup fails.
    with _db(websocket) as db:
        await _serve_device(websocket, db)


async def _serve_device(websocket: WebSocket, db: Session):
    manager = websocket.app.state.ws_manager
    device_id = websocket.query_params.get("device_id")
    token = _bearer_token(websocket)
    frame_budget = FrameBudget(websocket.app.state.settings)
    control_limiter = WebSocketRateLimiter(
        websocket.app.state.settings.rate_limit_ws_control_per_second
    )

    try:
        device = db.get(Device, device_id) if device_id else None
        if device is None or token is None or device.revoked_at is not None:
            logger.warning("Device connection rejected: invalid credentials")
            await websocket.close(code=4401)
            return
        if device.token_hash != hash_secret(token):
            logger.warning("Device connection rejected: invalid token")
            await websocket.close(code=4401)
            return

        if not await manager.connect_device(device.id, websocket):
            # A close before accept becomes HTTP 403 on the wire. Credentials are
            # valid here: convey the transient conflict without invalidating Android.
            await websocket.accept()
            await websocket.close(code=4409, reason="device_already_connected")
            return
        # Revocation may commit while the handshake is awaiting network I/O.
        db.refresh(device)
        if device.revoked_at is not None:
            await websocket.close(code=4401)
            return
        logger.info(f"Device WebSocket accepted: device_id={device_id}")

        device.status = "online"
        device.last_seen_at = utc_now()
        write_audit(db, "device_online", owner_id=device.owner_id, device_id=device.id)
        db.commit()

        await websocket.send_json(
            {
                "type": "device_registered",
                "deviceId": device.id,
                "status": "online",
                "serverTime": utc_now().isoformat() + "Z",
            }
        )

        while True:
            db.rollback()
            incoming = await websocket.receive()
            if manager.device_connections.get(device_id) is not websocket:
                break
            if incoming["type"] == "websocket.disconnect":
                raise WebSocketDisconnect(incoming.get("code", 1000))

            payload = incoming.get("bytes")
            if payload is not None:
                if not frame_budget.accept(len(payload)):
                    await websocket.close(code=4429, reason="screen_rate_limit")
                    break
                try:
                    header = parse_screen_frame_header(payload)
                except ValueError:
                    await websocket.send_json(
                        {
                            "type": "error_event",
                            "code": "INVALID_SCREEN_FRAME",
                            "message": "Frame binario non valido",
                        }
                    )
                    continue
                session_id = header["sessionId"]
                route = manager.get_route(session_id)
                if route is None or route.device_id != device_id:
                    await websocket.send_json(
                        {
                            "type": "session_error",
                            "sessionId": session_id,
                            "code": "SESSION_NOT_AUTHORIZED",
                            "message": "Sessione non valida",
                        }
                    )
                    continue
                await manager.forward_to_console_by_session(session_id, payload)
                continue

            # Binary frames use the live route; only control messages need database state.
            if not await allow_control(
                websocket, "ws-device-control", device_id, control_limiter
            ):
                break
            device = db.get(Device, device_id, populate_existing=True)
            if device is None or device.revoked_at is not None:
                await websocket.close(code=4401)
                break
            device.last_seen_at = utc_now()
            try:
                message = parse_control(incoming.get("text", ""), device=True)
            except (TypeError, ValueError):
                await websocket.send_json(
                    {
                        "type": "error_event",
                        "code": "INVALID_MESSAGE",
                        "message": "Messaggio JSON non valido",
                    }
                )
                continue
            message_type = message.get("type")
            session_id = message.get("sessionId")
            if session_id:
                route = manager.get_route(session_id)
                if route is None or route.device_id != device.id:
                    await websocket.send_json(
                        {"type": "session_error", "code": "SESSION_NOT_AUTHORIZED"}
                    )
                    continue

            if message_type == "device_local_stop":
                write_audit(
                    db,
                    "device_local_stop",
                    owner_id=device.owner_id,
                    device_id=device.id,
                    payload={"reason": message["reason"]},
                )
                db.commit()
            elif message_type == "device_hello":
                device.capabilities_json = message.get("capabilities") or {}
                db.commit()
                await websocket.send_json(
                    {
                        "type": "device_registered",
                        "deviceId": device.id,
                        "status": device.status,
                        "serverTime": utc_now().isoformat() + "Z",
                    }
                )
            elif message_type == "heartbeat":
                session_id = message.get("sessionId")
                if session_id:
                    session = db.get(RemoteSession, session_id)
                    if session:
                        session.last_heartbeat_at = utc_now()
                db.commit()
                await websocket.send_json(
                    {"type": "heartbeat_ack", "source": "backend"}
                )
            elif message_type == "session_error":
                await manager.forward_to_console_by_session(
                    message.get("sessionId"), message
                )
            elif message_type == "session_end":
                session = db.get(RemoteSession, message.get("sessionId"))
                if session and session.status == "in_session":
                    logger.info(
                        f"Session end requested by device: session_id={session.id}"
                    )
                    await _end_sessions(
                        db,
                        websocket,
                        [session.id],
                        message.get("reason") or "device_closed",
                        notify_device=False,
                    )
            else:
                await websocket.send_json(
                    {
                        "type": "error_event",
                        "code": "UNKNOWN_MESSAGE",
                        "message": message_type,
                    }
                )
    except WebSocketDisconnect:
        logger.info(f"Device WebSocket disconnected: device_id={device_id}")
    finally:
        connected = device_id and manager.device_connections.get(device_id) is websocket
        if connected:
            await _cleanup_device(db, websocket, device_id, manager)


async def _cleanup_device(db, websocket, device_id, manager):
    ended_session_ids = manager.disconnect_device(device_id)
    if device_id:
        device = db.get(Device, device_id)
        if device and device.revoked_at is None:
            device.status = "offline"
            write_audit(
                db, "device_offline", owner_id=device.owner_id, device_id=device.id
            )
    await _end_sessions(
        db, websocket, ended_session_ids, "device_disconnected", notify_device=False
    )


@router.websocket("/console/ws")
async def console_ws(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin and origin not in websocket.app.state.settings.allowed_origins_list:
        await websocket.close(code=4403)
        return
    if not await allow_upgrade(websocket):
        return
    # Cover authentication, handshake, registration and cleanup with one lifetime.
    with _db(websocket) as db:
        await _serve_console(websocket, db)


async def _serve_console(websocket: WebSocket, db: Session):
    manager = websocket.app.state.ws_manager
    challenges = DeviceChallenges(websocket.app.state.settings.max_remote_sessions)
    control_limiter = WebSocketRateLimiter(
        websocket.app.state.settings.rate_limit_ws_control_per_second
    )
    token = _bearer_token(websocket)
    user = authenticate_user(db, token or "", websocket.app.state.settings)

    if user is None:
        logger.warning("Console connection rejected: invalid token")
        await websocket.close(code=4401)
        return

    connection_id = generate_id("console")
    owner_id = user.id
    db.rollback()
    if not manager.reserve_console(connection_id, owner_id):
        await reject_connection(websocket, 4429, "console_connection_limit")
        return
    try:
        await websocket.accept(
            subprotocol="mydesk"
            if "mydesk" in websocket.scope.get("subprotocols", [])
            else None
        )
        logger.info(
            f"Console WebSocket accepted: connection_id={connection_id}, user_id={owner_id}"
        )
        await manager.connect_console(connection_id, owner_id, websocket)
        await websocket.send_json(
            {"type": "console_registered", "connectionId": connection_id}
        )
        while True:
            # End the read transaction so credential revocations are visible on
            # PostgreSQL as well as SQLite, including on idle connections.
            db.rollback()
            try:
                incoming = await asyncio.wait_for(
                    websocket.receive(), timeout=AUTH_RECHECK_SECONDS
                )
            except TimeoutError:
                incoming = None
            if incoming is not None:
                if incoming["type"] == "websocket.disconnect":
                    raise WebSocketDisconnect(incoming.get("code", 1000))
                if not await allow_control(
                    websocket, "ws-console-control", owner_id, control_limiter
                ):
                    break
            # Recheck once per accepted message or idle timeout, after the cheap
            # connection limit so a burst cannot trigger extra database work.
            user = authenticate_user(db, token or "", websocket.app.state.settings)
            if user is None:
                logger.warning(
                    f"Console authentication failed during session: connection_id={connection_id}"
                )
                await websocket.close(code=4401)
                break
            if incoming is None:
                continue
            try:
                message = parse_control(incoming.get("text", ""))
            except (TypeError, ValueError):
                await websocket.send_json(
                    {"type": "error_event", "code": "INVALID_MESSAGE"}
                )
                continue
            message_type = message.get("type")

            if message_type == "heartbeat":
                await websocket.send_json(
                    {"type": "heartbeat_ack", "source": "backend"}
                )
            elif message_type == "device_list_request":
                try:
                    enforce_limit(websocket.app, "devices", user.id, 30, 60)
                except HTTPException as error:
                    db.rollback()
                    await websocket.send_json(
                        {
                            "type": "error_event",
                            "code": "RATE_LIMITED"
                            if error.status_code == 429
                            else "SERVICE_UNAVAILABLE",
                            "retryAfter": int(
                                (error.headers or {}).get("Retry-After", "1")
                            ),
                        }
                    )
                    continue
                devices = db.scalars(
                    select(Device).where(Device.owner_id == user.id)
                ).all()
                await websocket.send_json(
                    {
                        "type": "device_list",
                        "devices": [serialize_device(device) for device in devices],
                    }
                )
            elif message_type in {"session_challenge_request", "session_start_request"}:
                logger.debug(f"Session start request: connection_id={connection_id}")
                try:
                    enforce_limit(
                        websocket.app,
                        "session-challenge"
                        if message_type == "session_challenge_request"
                        else "session-start",
                        user.id,
                        5,
                        60,
                    )
                except HTTPException:
                    await websocket.send_json(
                        {
                            "type": "session_error",
                            "deviceId": message.get("deviceId"),
                            "code": "RATE_LIMITED",
                        }
                    )
                    continue
                if message_type == "session_challenge_request":
                    await _handle_session_challenge(
                        db, websocket, user, message, challenges
                    )
                else:
                    await _handle_session_start(
                        db, websocket, user, connection_id, message, challenges
                    )
            elif message_type in {
                "input_tap",
                "input_swipe",
                "input_global_action",
                "input_text",
            }:
                session_id = message.get("sessionId")
                session = db.get(RemoteSession, session_id)
                if (
                    session is None
                    or session.owner_id != user.id
                    or session.status != "in_session"
                    or session.console_connection_id != connection_id
                ):
                    logger.warning(
                        f"Input message rejected: session_id={session_id}, type={message_type}"
                    )
                    await websocket.send_json(
                        {
                            "type": "session_error",
                            "sessionId": session_id,
                            "code": "SESSION_NOT_AUTHORIZED",
                            "message": "Sessione non valida",
                        }
                    )
                    continue
                logger.debug(
                    f"Forwarding input {message_type} to device: session_id={session_id}"
                )
                await manager.forward_to_device_by_session(session_id, message)
            elif message_type == "session_end":
                session = db.get(RemoteSession, message.get("sessionId"))
                if (
                    session
                    and session.owner_id == user.id
                    and session.status == "in_session"
                    and session.console_connection_id == connection_id
                ):
                    logger.info(
                        f"Session end requested by console: session_id={session.id}"
                    )
                    await _end_sessions(
                        db,
                        websocket,
                        [session.id],
                        message.get("reason") or "user_closed",
                        notify_console=True,
                    )
            else:
                await websocket.send_json(
                    {
                        "type": "error_event",
                        "code": "UNKNOWN_MESSAGE",
                        "message": message_type,
                    }
                )
    except WebSocketDisconnect:
        logger.info(f"Console WebSocket disconnected: connection_id={connection_id}")
    finally:
        challenges.pending.clear()
        manager.release_console_reservation(connection_id)
        ended_session_ids = (
            manager.disconnect_console(connection_id)
            if connection_id in manager.console_connections
            else []
        )
        await _end_sessions(
            db,
            websocket,
            ended_session_ids,
            "console_disconnected",
            notify_console=False,
        )


async def _handle_session_challenge(db, websocket, user, message, challenges):
    device_id = message["deviceId"]
    device = db.get(Device, device_id)
    if device is None or device.owner_id != user.id or device.revoked_at is not None:
        response = {
            "type": "session_error",
            "deviceId": device_id,
            "code": "DEVICE_NOT_FOUND",
        }
    elif not websocket.app.state.ws_manager.is_device_online(device_id):
        response = {
            "type": "session_error",
            "deviceId": device_id,
            "code": "DEVICE_OFFLINE",
        }
    else:
        challenge = challenges.issue(device, message["clientNonce"])
        response = (
            challenge.response()
            if challenge
            else {
                "type": "session_error",
                "deviceId": device_id,
                "code": "CHALLENGE_LIMIT",
            }
        )
    db.rollback()
    await websocket.send_json(response)


async def _handle_session_start(
    db: Session,
    websocket: WebSocket,
    user: User,
    connection_id: str,
    message: dict[str, Any],
    challenges: DeviceChallenges,
) -> None:
    logger.info(
        f"Handling session start: user_id={user.id}, connection_id={connection_id}"
    )
    manager = websocket.app.state.ws_manager
    device_id = message["deviceId"]
    challenge = challenges.consume(device_id, message["challengeId"])
    # Serialize quota checks and insertion across all connections for this owner.
    # Every branch releases the write lock before awaiting network I/O.
    AuthService(db, websocket.app.state.settings)._lock_user(user.id)
    if (
        authenticate_user(
            db, _bearer_token(websocket) or "", websocket.app.state.settings
        )
        is None
    ):
        db.rollback()
        await websocket.close(code=4401)
        return
    sessions = db.scalars(
        select(RemoteSession.id).where(
            RemoteSession.owner_id == user.id,
            RemoteSession.status == "in_session",
        )
    ).all()
    if len(sessions) >= websocket.app.state.settings.max_remote_sessions:
        db.rollback()
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device_id,
                "code": "SESSION_LIMIT",
                "message": "Limite sessioni raggiunto",
            }
        )
        return
    device = db.get(Device, device_id)

    if device is None or device.owner_id != user.id or device.revoked_at is not None:
        logger.warning(
            f"Session start rejected: device not found or not authorized, device_id={device_id}"
        )
        db.rollback()
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device_id,
                "code": "DEVICE_NOT_FOUND",
                "message": "Device non trovato",
            }
        )
        return
    if not manager.is_device_online(device.id):
        logger.warning(f"Session start rejected: device offline, device_id={device_id}")
        db.rollback()
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device_id,
                "code": "DEVICE_OFFLINE",
                "message": "Device offline",
            }
        )
        return
    server_proof = (
        verify_proof(
            device.access_auth_stored_key,
            device.access_auth_server_key,
            challenge.transcript,
            message["proof"],
        )
        if challenge
        else None
    )
    if server_proof is None:
        write_audit(
            db,
            "session_failed",
            owner_id=user.id,
            device_id=device.id,
            payload={"reason": "auth_failed"},
        )
        db.commit()
        logger.warning(
            f"Session start rejected: invalid device password, device_id={device_id}"
        )
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device.id,
                "code": "AUTH_FAILED",
                "message": "Password device non valida",
            }
        )
        return

    active_session = db.scalar(
        select(RemoteSession)
        .where(RemoteSession.device_id == device.id)
        .where(RemoteSession.status == "in_session")
    )
    if active_session is not None:
        logger.warning(
            f"Session start rejected: session already active, device_id={device_id}"
        )
        db.rollback()
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device_id,
                "code": "SESSION_ALREADY_ACTIVE",
                "message": "Device gia' in sessione",
            }
        )
        return

    session = RemoteSession(
        id=generate_id("sess"),
        device_id=device.id,
        owner_id=user.id,
        status="in_session",
        console_connection_id=connection_id,
        device_connection_id=device.id,
        last_heartbeat_at=utc_now(),
    )
    device.status = "in_session"
    db.add(session)
    write_audit(
        db,
        "session_opened",
        owner_id=user.id,
        device_id=device.id,
        session_id=session.id,
    )
    db.commit()

    manager.bind_session(session.id, device.id, connection_id)
    delivered = await manager.send_to_device(
        device.id,
        {"type": "session_start", "sessionId": session.id, "requestedBy": "owner"},
    )
    if not delivered:
        await _end_sessions(
            db,
            websocket,
            [session.id],
            "device_unavailable",
            notify_device=False,
            notify_console=False,
        )
        await websocket.send_json(
            {
                "type": "session_error",
                "deviceId": device.id,
                "code": "DEVICE_OFFLINE",
                "message": "Device non raggiungibile",
            }
        )
        return
    logger.info(
        f"Session started successfully: session_id={session.id}, device_id={device.id}"
    )
    await websocket.send_json(
        {
            "type": "session_started",
            "sessionId": session.id,
            "deviceId": device.id,
            "status": "in_session",
            "serverProof": server_proof,
        }
    )
