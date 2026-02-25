"""Serialize/deserialize cache values to/from JSON."""
from __future__ import annotations

import json
from typing import Any

from vibewall.models import CheckResult, CheckStatus


def serialize(value: Any) -> str:
    wrapped = _wrap(value)
    return json.dumps(wrapped, default=_encode)


def deserialize(raw: str) -> Any:
    decoded = json.loads(raw, object_hook=_decode)
    return _unwrap(decoded)


def _wrap(obj: Any) -> Any:
    """Recursively wrap tuples and lists so they survive JSON round-trip."""
    if isinstance(obj, tuple):
        return {"__type__": "tuple", "items": [_wrap(item) for item in obj]}
    if isinstance(obj, list):
        return {"__type__": "list", "items": [_wrap(item) for item in obj]}
    return obj


def _unwrap(obj: Any) -> Any:
    """Recursively unwrap tagged tuples/lists after JSON decode."""
    if isinstance(obj, dict):
        t = obj.get("__type__")
        if t == "tuple":
            return tuple(_unwrap(item) for item in obj["items"])
        if t == "list":
            return [_unwrap(item) for item in obj["items"]]
    if isinstance(obj, list):
        return [_unwrap(item) for item in obj]
    return obj


def _encode(obj: object) -> Any:
    if isinstance(obj, CheckResult):
        return {
            "__type__": "CheckResult",
            "status": obj.status.value,
            "reason": obj.reason,
            "data": obj.data,
        }
    if isinstance(obj, CheckStatus):
        return obj.value
    raise TypeError(f"Cannot serialize {type(obj)}")


def _decode(d: dict[str, Any]) -> Any:
    if d.get("__type__") == "CheckResult":
        return CheckResult(
            status=CheckStatus(d["status"]),
            reason=d["reason"],
            data=d.get("data", {}),
        )
    return d
