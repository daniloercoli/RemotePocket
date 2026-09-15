"""
MyDesk Server - Configurazione della Logging Strutturata

Questo file gestisce la configurazione del logging con output JSON strutturato
per ambienti di produzione. Il logging è fondamentale per il monitoring e il
debugging delle applicazioni distribuite.

La struttura JSON permette di:
- Analizzare i log con strumenti come ELK Stack o Splunk
- Tracciare richieste attraverso più servizi usando correlation ID
- Filtrare log per livello, modulo, o utente

Per l'alerting, consultare docs/alert-rules.md

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

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class StructuredJsonFormatter(logging.Formatter):
    """
    Formattatore per log strutturato in JSON.

    Questo formattatore converte ogni record di log in un oggetto JSON
    contenente metadata utili per il monitoring e il debugging.

    Campi inclusi:
    - timestamp: Orario del log
    - level: Livello di log (INFO, ERROR, ecc.)
    - logger: Nome del logger
    - message: Messaggio del log
    - request_id: ID di tracciamento della richiesta (se disponibile)
    - user_id: ID utente (se disponibile)
    - module/function/line: Origine del log

    In ambiente di sviluppo, il JSON è formattato con indentazione per
    leggibilità. In produzione, è compatto per ridurre la banda.
    """

    def __init__(self, environment: str = "dev"):
        """
        Inizializza il formattatore.

        Args:
            environment: Tipo di ambiente ('dev' per sviluppo, altro per produzione)
        """
        super().__init__()
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        """
        Converte un record di log in una stringa JSON.

        Args:
            record: Il record di log da formattare

        Returns:
            Stringa JSON contenente tutti i campi del log
        """
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Aggiunge correlation ID se disponibile per tracciare richieste
        if hasattr(record, "request_id"):
            log_data["request_id"] = record.request_id

        # Aggiunge user ID per tracciare azioni utente
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id

        # Campi extra per richieste HTTP
        if hasattr(record, "endpoint"):
            log_data["endpoint"] = record.endpoint
        if hasattr(record, "method"):
            log_data["method"] = record.method
        if hasattr(record, "duration"):
            log_data["duration_ms"] = record.duration
        if hasattr(record, "status"):
            log_data["status"] = record.status

        # Exception messages and tracebacks can contain SQL parameters or payloads.
        if record.exc_info:
            log_data["error_type"] = record.exc_info[0].__name__

        # Aggiunge campi extra se forniti
        if hasattr(record, "extra_fields"):
            log_data.update(record.extra_fields)

        if self.environment == "dev":
            # Formato leggibile per sviluppo
            return json.dumps(log_data, indent=2, ensure_ascii=False)
        else:
            # Formato compatto per produzione
            return json.dumps(log_data, separators=(",", ":"), ensure_ascii=False)


class CorrelationIdFilter(logging.Filter):
    """
    Filtro per aggiungere correlation ID ai log.

    Questo filtro cerca l'ID di tracciamento della richiesta e lo aggiunge
    a ogni record di log, permettendo di seguire una richiesta attraverso
    più log entries.

    Se l'ID non è già nel record, cerca nel context manager di correlation.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Aggiunge correlation ID e user ID ai log.

        Args:
            record: Il record di log da filtrare

        Returns:
            True per permettere la registrazione
        """
        if not hasattr(record, "request_id"):
            # Cerca l'ID nel context manager di correlation
            from app.correlation import get_request_id

            record.request_id = get_request_id()
        if not hasattr(record, "user_id"):
            record.user_id = None
        return True


def setup_logging(environment: str = "dev", log_level: str | None = None) -> None:
    """
    Configura il logging strutturato per l'applicazione.

    Questa funzione setuppa il logging con:
    - Formatter JSON strutturato
    - Filter per correlation ID
    - Handler console per output
    - Livelli di log configurabili per modulo

    Args:
        environment: Nome dell'ambiente ('dev', 'staging', 'prod')
        log_level: Livello di log (default: DEBUG per dev, INFO altrimenti)
    """
    # Imposta livello di log di default
    if log_level is None:
        log_level = "DEBUG" if environment == "dev" else "INFO"

    # Recupera il root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Rimuove handler esistenti per evitare duplicati
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Crea il formattatore
    formatter = StructuredJsonFormatter(environment=environment)

    # Crea handler per console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(CorrelationIdFilter())
    root_logger.addHandler(console_handler)

    # Silenzia log di librerie esterne troppo verbose
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    # Imposta livello per l'applicazione
    logging.getLogger("app").setLevel(getattr(logging, log_level.upper()))
