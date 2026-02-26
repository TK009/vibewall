from __future__ import annotations

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.base import BaseCheck
from vibewall.validators.rules import RuleSet


class PypiRulesCheck(BaseCheck):
    name = "pypi_rules"
    abbrev = "RUL"
    depends_on: list[str] = []
    scope = "pypi"

    def __init__(self, ruleset: RuleSet, **kwargs) -> None:
        self._ruleset = ruleset

    async def run(self, target: str, context: CheckContext) -> CheckResult:
        match = self._ruleset.match("pypi", target, method=context.method)
        if match is None:
            return CheckResult.ok(f"no rule matched for '{target}'", allowlisted=False)
        rule = match.rule
        source = f"{rule.source_file}:{rule.source_line}"
        if rule.action == "allow":
            return CheckResult.ok(
                f"allowed by rule: {rule.pattern} ({source})",
                allowlisted=True,
                rule_source=rule.source_file,
                rule_line=rule.source_line,
                rule_pattern=rule.pattern,
            )
        return CheckResult.fail(
            f"matched {rule.action} rule: {rule.pattern} ({source})",
            action_override=rule.action,
            rule_source=rule.source_file,
            rule_line=rule.source_line,
            rule_pattern=rule.pattern,
        )
