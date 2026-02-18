from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    reason: str

    @staticmethod
    def allow(reason: str = "ok") -> ValidationResult:
        return ValidationResult(allowed=True, reason=reason)

    @staticmethod
    def block(reason: str) -> ValidationResult:
        return ValidationResult(allowed=False, reason=reason)
