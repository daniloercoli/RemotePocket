"""Bounded draining shared by the ASGI lifespan and the production Uvicorn runner.

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
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ShutdownConfig:
    timeout_seconds: float = 30
    websocket_drain_timeout: float = 10


class GracefulShutdownHandler:
    def __init__(self, config=None):
        self.config = config or ShutdownConfig()
        self.is_shutdown_initiated = False
        self.active_requests = 0
        self._task = None

    def begin_shutdown(self):
        self.is_shutdown_initiated = True

    async def initiate_shutdown(self, app):
        self.begin_shutdown()
        if self._task is None:
            self._task = asyncio.create_task(self._drain(app))
        await asyncio.shield(self._task)

    async def _drain(self, app):
        manager = app.state.ws_manager
        sockets = list(manager.device_connections.values()) + [
            c.websocket for c in manager.console_connections.values()
        ]

        async def close(websocket):
            try:
                await websocket.close(code=1001, reason="Server shutdown")
            except Exception:
                logger.warning("WebSocket close failed during shutdown")

        async def drain():
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(close(ws) for ws in sockets)),
                    self.config.websocket_drain_timeout,
                )
            except TimeoutError:
                logger.warning("WebSocket drain timed out")
            while self.active_requests:
                await asyncio.sleep(0.02)

        try:
            await asyncio.wait_for(drain(), self.config.timeout_seconds)
        except TimeoutError:
            logger.warning("Request drain timed out")
        logger.info("Connection drain completed")
