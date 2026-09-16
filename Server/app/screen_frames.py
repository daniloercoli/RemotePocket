from __future__ import annotations

import json


MAX_FRAME_HEADER_BYTES = 16 * 1024


def parse_screen_frame_header(payload: bytes) -> dict:
    """Read a little-endian uint32 length, UTF-8 JSON header and JPEG bytes."""
    if len(payload) < 4:
        raise ValueError("Missing frame header length")
    header_length = int.from_bytes(payload[:4], "little")
    if not 0 < header_length <= MAX_FRAME_HEADER_BYTES or 4 + header_length >= len(
        payload
    ):
        raise ValueError("Invalid frame header length or empty image")
    try:
        header = json.loads(payload[4 : 4 + header_length].decode("utf-8"))
    except RecursionError as error:
        raise ValueError("Frame header nesting too deep") from error
    if not isinstance(header, dict) or header.get("type") != "screen_frame":
        raise ValueError("Expected a screen_frame header")
    if header.get("format") != "jpeg":
        raise ValueError("Expected JPEG image data")
    if not isinstance(header.get("sessionId"), str) or not header["sessionId"]:
        raise ValueError("Missing frame session")
    for field in ("width", "height"):
        if type(header.get(field)) is not int or header[field] <= 0:
            raise ValueError("Invalid frame dimensions")
    if type(header.get("frameId")) is not int or header["frameId"] < 0:
        raise ValueError("Invalid frame ID")
    return header
