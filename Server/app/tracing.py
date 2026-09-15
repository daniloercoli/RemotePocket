"""Per-application tracing providers, configured before the ASGI stack is built.

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

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter as GRPCExporter,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter as HTTPExporter,
)
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.trace import SpanKind, StatusCode
from sqlalchemy import event
from starlette.datastructures import URL
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def setup_tracing(
    service_name="mydesk-server",
    environment="dev",
    otlp_endpoint=None,
    otlp_protocol="http",
    otlp_insecure=False,
) -> TracerProvider:
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": service_name,
                "service.version": "0.1.0",
                "deployment.environment": environment,
            }
        )
    )
    if otlp_endpoint:
        exporter = (
            GRPCExporter(endpoint=otlp_endpoint, insecure=otlp_insecure)
            if otlp_protocol == "grpc"
            else HTTPExporter(endpoint=otlp_endpoint)
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
    return provider


def instrument(app, engine, provider):
    def safe_request_attributes(span, scope):
        if span.is_recording():
            if scope["type"] == "websocket":
                # FastAPI's included-router wrapper does not expose a WS route name.
                path = (
                    scope["path"]
                    if scope["path"] in {"/console/ws", "/device/ws"}
                    else "/unmatched"
                )
                span.update_name("WEBSOCKET " + path)
            url = str(URL(scope=scope).replace(query=""))
            span.set_attribute("http.url", url)
            span.set_attribute("url.full", url)
            span.set_attribute("url.query", "")

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        server_request_hook=safe_request_attributes,
        excluded_urls="api/health,metrics",
        http_capture_headers_server_request=[],
        http_capture_headers_server_response=[],
        http_capture_headers_sanitize_fields=[".*"],
        exclude_spans=["receive", "send"],
    )
    # SQLAlchemy's global instrumentor binds all factories to the first provider.
    # Engine-local event listeners keep separately configured apps isolated.
    tracer = provider.get_tracer("mydesk.database")

    @event.listens_for(engine, "before_cursor_execute")
    def before_query(conn, cursor, statement, parameters, execution_context, many):
        execution_context.mydesk_span = tracer.start_span(
            "db.query",
            kind=SpanKind.CLIENT,
            attributes={"db.system.name": engine.dialect.name},
        )

    @event.listens_for(engine, "after_cursor_execute")
    def after_query(conn, cursor, statement, parameters, execution_context, many):
        span = getattr(execution_context, "mydesk_span", None)
        if span is not None:
            span.end()
            execution_context.mydesk_span = None

    @event.listens_for(engine, "handle_error")
    def query_error(error_context):
        execution_context = error_context.execution_context
        span = getattr(execution_context, "mydesk_span", None)
        if span is not None:
            span.set_status(StatusCode.ERROR)
            span.end()
            execution_context.mydesk_span = None
