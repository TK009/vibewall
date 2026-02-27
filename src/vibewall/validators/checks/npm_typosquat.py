from __future__ import annotations

from rapidfuzz.distance import Levenshtein

from vibewall.models import CheckContext, CheckResult, CheckStatus
from vibewall.validators.base import BaseCheck
from vibewall.validators.rules import RuleSet

_MIN_TYPOSQUAT_NAME_LEN = 6


class NpmTyposquatCheck(BaseCheck):
    name = "npm_typosquat"
    abbrev = "TYP"
    depends_on = ("npm_registry", "npm_rules")
    scope = "npm"
    default_action = "warn"

    def __init__(self, ruleset: RuleSet, max_distance: int = 2, **kwargs) -> None:
        self._ruleset = ruleset
        self._max_distance = max_distance

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        # If allowlisted, skip typosquat check
        rules_data = context.data("npm_rules")
        if rules_data.get("allowlisted"):
            return CheckResult.ok("allowlisted, skipping typosquat check")

        # Skip short names — edit distance 2 from a 3-4 char name covers too
        # much of the namespace (false positives).
        if len(target) < _MIN_TYPOSQUAT_NAME_LEN:
            return CheckResult.ok(
                f"name too short ({len(target)} chars) for typosquat check"
            )

        for known in self._ruleset.allowlisted_names("npm"):
            if known == target:
                continue
            dist = Levenshtein.distance(
                target, known, score_cutoff=self._max_distance
            )
            if dist <= self._max_distance:
                return CheckResult.fail(
                    f"package '{target}' looks like a typosquat of '{known}' "
                    f"(edit distance: {dist})",
                    similar_to=known,
                    edit_distance=dist,
                )

        return CheckResult.ok(f"package '{target}' is not a typosquat")
