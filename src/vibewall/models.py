from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CheckStatus(Enum):
    OK = "ok"
    SUS = "sus"
    FAIL = "fail"
    ERR = "err"


@dataclass(frozen=True)
class CheckResult:
    status: CheckStatus
    reason: str
    data: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def ok(reason: str = "ok", **data: Any) -> CheckResult:
        return CheckResult(status=CheckStatus.OK, reason=reason, data=data)

    @staticmethod
    def fail(reason: str, **data: Any) -> CheckResult:
        return CheckResult(status=CheckStatus.FAIL, reason=reason, data=data)

    @staticmethod
    def err(reason: str) -> CheckResult:
        return CheckResult(status=CheckStatus.ERR, reason=reason)

    @staticmethod
    def sus(reason: str, **data: Any) -> CheckResult:
        return CheckResult(status=CheckStatus.SUS, reason=reason, data=data)


class CheckContext:
    """Carries accumulated data from completed dependency checks."""

    def __init__(self, *, version: str | None = None) -> None:
        self._results: dict[str, CheckResult] = {}
        self.version = version

    def add(self, name: str, result: CheckResult) -> None:
        self._results[name] = result

    def get(self, name: str) -> CheckResult | None:
        return self._results.get(name)

    def data(self, name: str) -> dict[str, Any]:
        result = self._results.get(name)
        if result is None:
            return {}
        return result.data


@dataclass(frozen=True)
class RunResult:
    """Aggregate result from running all checks."""

    allowed: bool
    reason: str
    results: list[tuple[str, CheckResult]]  # (check_name, result)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.allowed


@dataclass
class PipelineResult:
    """Wraps RunResult with an optional event for background checks."""

    run_result: RunResult
    background: asyncio.Event | None = field(default=None, repr=False)
