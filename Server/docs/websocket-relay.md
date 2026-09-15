# Redis WebSocket relay

The Redis relay is an experimental development feature for passing WebSocket messages between processes. It does not provide a supported deployment with multiple workers or instances. Run the backend with one worker and one instance.

## Enable for development

Start a Redis instance, then set these values in `Server/.env` and restart the development server:

```dotenv
MYDESK_ENVIRONMENT=dev
MYDESK_REDIS_URL=redis://localhost:6379/0
MYDESK_REDIS_RELAY_ENABLED=true
```

Staging and production reject `MYDESK_REDIS_RELAY_ENABLED=true`. The default is `false`; local development does not need Redis when the relay is disabled.

## Behavior

The relay carries JSON and binary frames and preserves request and tracing context. Each process ignores its own published messages. Received messages are not published again.

A direct message is acknowledged by the process that owns the destination connection. A missing destination, timeout, full queue or Redis failure returns a delivery failure.

Queues are bounded and messages are not stored persistently. Redis Pub/Sub does not recover messages lost during a disconnection. A Redis failure makes the relay unhealthy and readiness unavailable; restart the backend after restoring Redis.

## Tests

From `Server`, with development dependencies installed:

```bash
python -m pytest -q tests/test_websocket_relay.py
```

The tests use a local `redis-server`, or the test instance specified by `MYDESK_TEST_REDIS_URL`. They use separate channels and cover JSON, binary frames, tracing context, missing destinations, full queues and prevention of message loops.
