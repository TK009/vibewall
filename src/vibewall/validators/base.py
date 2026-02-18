from __future__ import annotations

from abc import ABC, abstractmethod

from vibewall.models import ValidationResult


class BaseValidator(ABC):
    @abstractmethod
    async def validate(self, target: str) -> ValidationResult:
        """Validate a target (package name or URL). Returns ValidationResult."""
        ...
