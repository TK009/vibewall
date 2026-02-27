"""Unified rules engine for allowlist/blocklist matching with regex and method filtering."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import structlog

from vibewall.exceptions import ConfigError

logger = structlog.get_logger()

_VALID_ACTIONS = frozenset({
    "allow", "block", "warn",
    "ask-allow", "ask-block",
    "ask-llm-allow", "ask-llm-block",
})

_SECTION_RE = re.compile(
    r"^\[\s*(\S+)"           # action
    r"\s+scope=(\S+)"        # scope=npm
    r"(?:\s+methods=(\S+))?" # optional methods=GET,POST
    r"\s*\]$"
)

_IMPORT_RE = re.compile(
    r"^@import\s+(\S+)"       # file path
    r"\s+\[(.+)\]$"           # [action scope=SCOPE]
)


@dataclass(frozen=True)
class Rule:
    action: str
    scope: str
    pattern: str
    is_regex: bool
    compiled: re.Pattern[str] | None
    exact: str | None
    methods: frozenset[str] | None
    source_file: str
    source_line: int


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    matched_value: str


class RuleSet:
    """Loads and matches rules from a rules file."""

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules
        # Pre-compute allowlisted exact names per scope for typosquat checks
        self._allowlisted: dict[str, frozenset[str]] = {}
        allow_by_scope: dict[str, set[str]] = {}
        for r in rules:
            if r.action == "allow" and not r.is_regex and r.exact is not None:
                allow_by_scope.setdefault(r.scope, set()).add(r.exact)
        for scope, names in allow_by_scope.items():
            self._allowlisted[scope] = frozenset(names)

        # Partition rules by scope for O(1) scope lookup
        self._by_scope: dict[str, list[Rule]] = {}
        for r in rules:
            self._by_scope.setdefault(r.scope, []).append(r)

        # Build exact-match prefix dict per scope.
        # Consecutive exact-match rules (no method filter) from the front of
        # each scope's list go into a dict for O(1) lookup.  First occurrence
        # wins (preserves first-match-wins semantics since the prefix comes
        # before any regex or method-filtered rule).
        self._exact_prefix: dict[str, dict[str, Rule]] = {}
        self._prefix_end: dict[str, int] = {}
        for scope, scope_rules in self._by_scope.items():
            prefix: dict[str, Rule] = {}
            end = 0
            for i, r in enumerate(scope_rules):
                if r.is_regex or r.methods is not None:
                    break
                if r.exact is not None and r.exact not in prefix:
                    prefix[r.exact] = r
                end = i + 1
            self._exact_prefix[scope] = prefix
            self._prefix_end[scope] = end

    @property
    def rules(self) -> list[Rule]:
        return self._rules

    def allowlisted_names(self, scope: str) -> frozenset[str]:
        """Return the set of exact-match allow rule names for a scope."""
        return self._allowlisted.get(scope, frozenset())

    @classmethod
    def load(cls, rules_path: Path, config_dir: Path) -> RuleSet:
        """Parse a rules file and return a RuleSet."""
        rules: list[Rule] = []
        if not rules_path.exists():
            logger.warning("rules_file_not_found", path=str(rules_path))
            return cls(rules)

        text = rules_path.read_text()
        current_action: str | None = None
        current_scope: str | None = None
        current_methods: frozenset[str] | None = None

        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header
            if line.startswith("["):
                m = _SECTION_RE.match(line)
                if m is None:
                    logger.warning("invalid_section_header", file=str(rules_path), line=lineno, text=line)
                    continue
                action, scope, methods_str = m.group(1), m.group(2), m.group(3)
                if action not in _VALID_ACTIONS:
                    logger.warning("invalid_action", file=str(rules_path), line=lineno, action=action)
                    continue
                current_action = action
                current_scope = scope
                current_methods = frozenset(methods_str.upper().split(",")) if methods_str else None
                continue

            # Import directive
            if line.startswith("@import"):
                m = _IMPORT_RE.match(line)
                if m is None:
                    logger.warning("invalid_import", file=str(rules_path), line=lineno, text=line)
                    continue
                import_file = m.group(1)
                import_header = m.group(2).strip()
                # Parse the bracketed section spec
                sm = _SECTION_RE.match(f"[{import_header}]")
                if sm is None:
                    logger.warning("invalid_import_spec", file=str(rules_path), line=lineno, text=line)
                    continue
                imp_action, imp_scope = sm.group(1), sm.group(2)
                imp_methods_str = sm.group(3)
                if imp_action not in _VALID_ACTIONS:
                    logger.warning("invalid_import_action", file=str(rules_path), line=lineno, action=imp_action)
                    continue
                imp_methods = frozenset(imp_methods_str.upper().split(",")) if imp_methods_str else None
                imp_path = config_dir / import_file
                if not imp_path.exists():
                    logger.warning("import_file_not_found", file=str(rules_path), line=lineno, import_path=str(imp_path))
                    continue
                imported = _load_plain_list(imp_path)
                for entry_line, entry in imported:
                    rules.append(Rule(
                        action=imp_action,
                        scope=imp_scope,
                        pattern=entry,
                        is_regex=False,
                        compiled=None,
                        exact=entry.lower(),
                        methods=imp_methods,
                        source_file=str(imp_path),
                        source_line=entry_line,
                    ))
                continue

            # Regular rule entry
            if current_action is None or current_scope is None:
                logger.warning("rule_outside_section", file=str(rules_path), line=lineno, text=line)
                continue

            try:
                rule = _parse_rule_entry(
                    line, current_action, current_scope, current_methods,
                    str(rules_path), lineno,
                )
            except ConfigError:
                continue
            if rule is not None:
                rules.append(rule)

        return cls(rules)

    def match(self, scope: str, target: str, method: str | None = None) -> RuleMatch | None:
        """Find the first matching rule for a target. Returns None if no match."""
        scope_rules = self._by_scope.get(scope)
        if not scope_rules:
            return None

        # Pre-compute normalized key and hostname once
        if scope == "url":
            hostname = (urlparse(target).hostname or "").lower()
            lookup_key = hostname
        else:
            lookup_key = target.lower()

        # Fast-path: check exact-match prefix dict (O(1))
        prefix = self._exact_prefix.get(scope)
        if prefix:
            rule = prefix.get(lookup_key)
            if rule is not None:
                matched = hostname if scope == "url" else target
                return RuleMatch(rule=rule, matched_value=matched)

        # Slow-path: linear scan from prefix-end onwards
        start = self._prefix_end.get(scope, 0)
        for rule in scope_rules[start:]:
            if rule.methods is not None and method is not None:
                if method.upper() not in rule.methods:
                    continue
            if rule.is_regex and rule.compiled is not None:
                if rule.compiled.search(target):
                    return RuleMatch(rule=rule, matched_value=target)
            elif rule.exact is not None:
                if scope == "url":
                    if hostname == rule.exact:
                        return RuleMatch(rule=rule, matched_value=hostname)
                else:
                    if lookup_key == rule.exact:
                        return RuleMatch(rule=rule, matched_value=target)
        return None


def _load_plain_list(path: Path) -> list[tuple[int, str]]:
    """Load a plain-text list file, returning (line_number, entry) pairs."""
    entries: list[tuple[int, str]] = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if line and not line.startswith("#"):
            entries.append((lineno, line))
    return entries


def _parse_rule_entry(
    text: str,
    action: str,
    scope: str,
    methods: frozenset[str] | None,
    source_file: str,
    source_line: int,
) -> Rule | None:
    """Parse a single rule entry (regex in /slashes/ or exact match)."""
    if text.startswith("/") and text.endswith("/") and len(text) > 1:
        pattern_str = text[1:-1]
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            logger.warning("invalid_regex", file=source_file, line=source_line, pattern=pattern_str, error=str(e))
            raise ConfigError(
                f"invalid regex '{pattern_str}' at {source_file}:{source_line}: {e}"
            ) from e
        return Rule(
            action=action,
            scope=scope,
            pattern=text,
            is_regex=True,
            compiled=compiled,
            exact=None,
            methods=methods,
            source_file=source_file,
            source_line=source_line,
        )
    else:
        return Rule(
            action=action,
            scope=scope,
            pattern=text,
            is_regex=False,
            compiled=None,
            exact=text.lower(),
            methods=methods,
            source_file=source_file,
            source_line=source_line,
        )
