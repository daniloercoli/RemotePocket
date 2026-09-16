"""Validate untrusted control messages before querying or forwarding them."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

Id = Annotated[str, Field(min_length=1, max_length=80)]
Coordinate = Annotated[float, Field(ge=0, le=32768, allow_inf_nan=False)]


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Heartbeat(Message):
    type: Literal["heartbeat"]
    sessionId: Id | None = None


class DeviceHello(Message):
    model_config = ConfigDict(extra="ignore")
    type: Literal["device_hello"]
    capabilities: dict = Field(default_factory=dict)


class DeviceStop(Message):
    type: Literal["device_local_stop"]
    reason: Literal["local_paused", "local_removed"]


class SessionEnd(Message):
    type: Literal["session_end"]
    sessionId: Id
    reason: str = Field(default="user_closed", max_length=80)


class SessionError(Message):
    type: Literal["session_error"]
    sessionId: Id
    code: str = Field(max_length=80)
    message: str = Field(default="", max_length=1000)


class DeviceList(Message):
    type: Literal["device_list_request"]


class SessionChallenge(Message):
    type: Literal["session_challenge_request"]
    deviceId: Id
    clientNonce: str = Field(pattern=r"^[a-f0-9]{64}$", min_length=64, max_length=64)


class SessionStart(Message):
    type: Literal["session_start_request"]
    deviceId: Id
    challengeId: Id
    proof: str = Field(pattern=r"^[A-Za-z0-9+/]{43}=$", min_length=44, max_length=44)


class Tap(Message):
    type: Literal["input_tap"]
    sessionId: Id
    x: Coordinate
    y: Coordinate
    screenWidth: int = Field(ge=1, le=32768)
    screenHeight: int = Field(ge=1, le=32768)


class Point(Message):
    x: Coordinate
    y: Coordinate


class Swipe(Message):
    type: Literal["input_swipe"]
    sessionId: Id
    from_: Point = Field(alias="from")
    to: Point
    durationMs: int = Field(default=450, ge=1, le=10000)


class GlobalAction(Message):
    type: Literal["input_global_action"]
    sessionId: Id
    action: Literal["BACK", "HOME", "RECENTS", "NOTIFICATIONS", "QUICK_SETTINGS"]


class InputText(Message):
    type: Literal["input_text"]
    sessionId: Id
    text: str = Field(max_length=10000)


DEVICE = TypeAdapter(
    Annotated[
        Heartbeat | DeviceHello | DeviceStop | SessionEnd | SessionError,
        Field(discriminator="type"),
    ]
)
CONSOLE = TypeAdapter(
    Annotated[
        Heartbeat
        | DeviceList
        | SessionChallenge
        | SessionStart
        | SessionEnd
        | Tap
        | Swipe
        | GlobalAction
        | InputText,
        Field(discriminator="type"),
    ]
)


def parse_control(raw, *, device=False):
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 64 * 1024:
        raise ValueError("Control message too large")
    return (
        (DEVICE if device else CONSOLE)
        .validate_json(raw)
        .model_dump(exclude_none=True, by_alias=True)
    )
