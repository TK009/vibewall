"""Serialize/deserialize cache values to/from JSON."""
from __future__ import annotations

import json
from typing import Any

from vibewall.models import CheckResult, CheckStatus


def serialize(value: Any) -> str:
    return json.dumps(value, default=_encode)


def deserialize(raw: str) -> Any:
    return json.loads(raw, object_hook=_decode)


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
