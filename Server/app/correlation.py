"""
MyDesk Server - Gestione Correlation ID per Tracciamento Richieste

Questo modulo gestisce correlation ID, valori univoci che permettono di
tracciare una richiesta attraverso tutta la catena di servizi. Questo è
fondamentale per debugging e monitoring in architetture distribuite.

Il correlation ID viene:
1. Generato all'ingresso di una richiesta
2. Aggiunto a tutti i log della richiesta
3. Trasmesso alle chiamate a servizi interni
4. Usato per correlare log multipli della stessa richiesta

Implementazione:
- Usa contextvars per supporto async/thread-safe

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

import contextlib
import contextvars
import uuid
from typing import Generator

# Context variable per correlation ID (thread-safe e async-safe)
# Ogni task/contesto ha il suo valore isolato
_request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)


def generate_request_id() -> str:
    """
    Genera un nuovo correlation ID univoco.
    
    Usa UUID4 per garantire unicità anche con molte richieste simultanee.
    
    Returns:
        Stringa UUID4 format (es: "f47ac10b-58cc-4372-a567-0e02b2c3d479")
    """
    return str(uuid.uuid4())


def get_request_id() -> str | None:
    """
    Recupera il correlation ID corrente.
    
    Returns:
        L'ID corrente o None se non impostato
    """
    return _request_id_var.get()


def set_request_id(request_id: str) -> contextvars.Token[str]:
    """
    Imposta il correlation ID e restituisce un token per il reset.
    
    Questo è usato per salvare lo stato precedente prima di sovrascrivere.
    
    Args:
        request_id: L'ID da impostare
        
    Returns:
        Token da usare con reset_request_id per ripristinare il valore precedente
    """
    return _request_id_var.set(request_id)


def reset_request_id(token: contextvars.Token[str]) -> None:
    """
    Resetta il correlation ID al valore precedente.
    
    Args:
        token: Token ottenuto da set_request_id
    """
    _request_id_var.reset(token)


@contextlib.contextmanager
def correlation_id_context(request_id: str | None = None) -> Generator[str, None, None]:
    """
    Context manager per gestire correlation ID automaticamente.
    
    Questo context manager:
    1. Imposta un correlation ID (nuovo o fornito)
    2. Esegue il blocco di codice
    3. Resetta automaticamente all'ID precedente
    
    Esempio:
        with correlation_id_context() as req_id:
            log.info("richiesta elaborata", extra={"request_id": req_id})
            # ID è disponibile ovunque durante l'esecuzione
        # ID è automaticamente resettato qui
    
    Args:
        request_id: ID da usare, o None per generarne uno nuovo
        
    Yields:
        L'ID di correlation usato
    """
    if request_id is None:
        request_id = generate_request_id()

    token = set_request_id(request_id)
    try:
        yield request_id
    finally:
        reset_request_id(token)


def extract_request_id_from_headers(headers: dict[str, str]) -> str | None:
    """
    Estrae correlation ID dagli headers HTTP.
    
    Legge l'header 'x-request-id' per mantenere il tracciamento
    attraverso chiamate di servizio.
    
    Args:
        headers: Dizionario degli headers HTTP
        
    Returns:
        L'ID estratto o None se non presente
    """
    return headers.get("x-request-id")


def set_request_id_in_headers(headers: dict[str, str], request_id: str) -> None:
    """
    Imposta correlation ID negli headers per propagazione.
    
    Questo permette di mantenere il tracciamento quando si chiamano
    altri servizi.
    
    Args:
        headers: Dizionario degli headers da modificare
        request_id: ID da impostare
    """
    headers["x-request-id"] = request_id