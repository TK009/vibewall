from __future__ import annotations

from rapidfuzz.distance import Levenshtein

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.allowlist import AllowBlockList
from vibewall.validators.base import BaseCheck

_MIN_TYPOSQUAT_NAME_LEN = 6


class PypiTyposquatCheck(BaseCheck):
    name = "pypi_typosquat"
    abbrev = "TYP"
    depends_on = ["pypi_registry", "pypi_allowlist"]
    scope = "pypi"
    default_action = "warn"

    def __init__(self, pypi_lists: AllowBlockList, max_distance: int = 2, **kwargs) -> None:
        self._lists = pypi_lists
        self._max_distance = max_distance

    async def run(self, target: str, context: CheckContext, **_kw: object) -> CheckResult:
        # If allowlisted, skip typosquat check
        allowlist_data = context.data("pypi_allowlist")
        if allowlist_data.get("allowlisted"):
            return CheckResult.ok("allowlisted, skipping typosquat check")

        # Skip short names — edit distance 2 from a 3-4 char name covers too
        # much of the namespace (false positives).
        if len(target) < _MIN_TYPOSQUAT_NAME_LEN:
            return CheckResult.ok(
                f"name too short ({len(target)} chars) for typosquat check"
            )

        for known in self._lists.allowlist:
            if known == target:
                continue
            dist = Levenshtein.distance(
                target, known, score_cutoff=self._max_distance
            )
            if dist <= self._max_distance:
                return CheckResult.fail(
                    f"package '{target}' looks like a typosquat of '{known}' "
                    f"(edit distance: {dist})"
                )

        return CheckResult.ok(f"package '{target}' is not a typosquat")
