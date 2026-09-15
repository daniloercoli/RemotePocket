"""Application-scoped Prometheus collectors; recording never opens a database connection.

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

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class Metrics:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "http_requests_total",
            "HTTP requests",
            ["method", "endpoint", "status"],
            registry=self.registry,
        )
        self.request_duration = Histogram(
            "request_duration_seconds",
            "HTTP request duration",
            ["method", "endpoint"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=self.registry,
        )
        self.auth_failures = Counter(
            "auth_failures_total",
            "Rejected authentication",
            ["auth_type"],
            registry=self.registry,
        )
        self.session_events = Counter(
            "session_events_total",
            "Remote session lifecycle",
            ["event_type"],
            registry=self.registry,
        )
        self.websocket_connections = Gauge(
            "active_websocket_connections",
            "Local live WebSockets",
            ["connection_type"],
            registry=self.registry,
        )
        self.websocket_disconnects = Counter(
            "websocket_disconnects_total",
            "Closed accepted WebSockets",
            ["connection_type"],
            registry=self.registry,
        )
        self.websocket_duration = Histogram(
            "websocket_message_duration_seconds",
            "WebSocket message processing time",
            ["message_type"],
            registry=self.registry,
        )
        self.active_sessions = Gauge(
            "active_sessions", "Local remote session routes", registry=self.registry
        )
        self.db_pool_connections = Gauge(
            "db_pool_connections", "Checked-out DB connections", registry=self.registry
        )
        self.db_pool_capacity = Gauge(
            "db_pool_capacity", "Configured DB pool capacity", registry=self.registry
        )
        self.ready = Gauge(
            "mydesk_ready",
            "Readiness of last probe (1 = healthy)",
            registry=self.registry,
        )

    def bind(self, manager, engine, pool_capacity: int) -> None:
        self.websocket_connections.labels(connection_type="device").set_function(
            lambda: len(manager.device_connections)
        )
        self.websocket_connections.labels(connection_type="console").set_function(
            lambda: len(manager.console_connections)
        )
        self.active_sessions.set_function(lambda: len(manager.session_routes))
        self.db_pool_connections.set_function(
            lambda: getattr(engine.pool, "checkedout", lambda: 0)()
        )
        self.db_pool_capacity.set(pool_capacity)

    def record_request(
        self, method: str, endpoint: str, status: int, duration: float
    ) -> None:
        if self.enabled:
            method = (
                method
                if method
                in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                else "OTHER"
            )
            self.http_requests.labels(method, endpoint, str(status)).inc()
            self.request_duration.labels(method, endpoint).observe(duration)

    def record_auth_failure(self, auth_type: str) -> None:
        if self.enabled:
            self.auth_failures.labels(auth_type).inc()

    def record_session_event(self, event_type: str) -> None:
        if self.enabled:
            self.session_events.labels(event_type).inc()
