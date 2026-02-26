"""Tests for the unified rules engine."""
from __future__ import annotations

from pathlib import Path

import pytest

from vibewall.models import CheckContext, CheckResult
from vibewall.validators.rules import Rule, RuleMatch, RuleSet
from vibewall.validators.checks.npm_rules import NpmRulesCheck
from vibewall.validators.checks.pypi_rules import PypiRulesCheck
from vibewall.validators.checks.url_rules import UrlRulesCheck


class TestRuleParsing:
    def test_section_and_exact_rules(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\n"
            "evil-package\n"
            "\n"
            "[allow scope=npm]\n"
            "lodash\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 2
        assert rs.rules[0].action == "block"
        assert rs.rules[0].exact == "evil-package"
        assert rs.rules[1].action == "allow"
        assert rs.rules[1].exact == "lodash"

    def test_regex_rules(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\n"
            "/evil-.*/\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1
        assert rs.rules[0].is_regex
        assert rs.rules[0].compiled is not None

    def test_invalid_regex_skipped(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\n"
            "/[invalid/\n"
            "valid-entry\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1
        assert rs.rules[0].exact == "valid-entry"

    def test_comments_and_blanks_ignored(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "# comment\n"
            "\n"
            "[block scope=npm]\n"
            "# another comment\n"
            "evil-pkg\n"
            "  \n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1

    def test_methods_filter(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=url methods=DELETE,POST]\n"
            "dangerous.com\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.rules[0].methods == frozenset({"DELETE", "POST"})

    def test_import_directive(self, tmp_path: Path) -> None:
        list_file = tmp_path / "blocklist.txt"
        list_file.write_text("evil-pkg\nbad-pkg\n")
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "@import blocklist.txt [block scope=npm]\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 2
        assert rs.rules[0].exact == "evil-pkg"
        assert rs.rules[0].action == "block"
        assert rs.rules[0].scope == "npm"
        assert rs.rules[1].exact == "bad-pkg"

    def test_import_missing_file_skipped(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "@import nonexistent.txt [block scope=npm]\n"
            "[block scope=npm]\n"
            "evil-pkg\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1

    def test_rule_outside_section_skipped(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("orphan-entry\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 0

    def test_invalid_section_header_skipped(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[invalid header]\n"
            "[block scope=npm]\n"
            "entry\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1

    def test_invalid_action_skipped(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[destroy scope=npm]\n"
            "entry\n"
            "[block scope=npm]\n"
            "valid\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == 1

    def test_source_tracking(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\n"
            "evil-pkg\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.rules[0].source_file == str(rules_file)
        assert rs.rules[0].source_line == 2

    def test_nonexistent_rules_file(self, tmp_path: Path) -> None:
        rs = RuleSet.load(tmp_path / "nope.txt", tmp_path)
        assert len(rs.rules) == 0

    def test_all_valid_actions(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        actions = ["allow", "block", "warn", "ask-allow", "ask-block", "ask-llm-allow", "ask-llm-block"]
        lines = []
        for action in actions:
            lines.append(f"[{action} scope=npm]")
            lines.append(f"{action}-pkg")
        rules_file.write_text("\n".join(lines) + "\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert len(rs.rules) == len(actions)
        for i, action in enumerate(actions):
            assert rs.rules[i].action == action

    def test_case_insensitive_exact(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=npm]\nEVIL-Pkg\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.rules[0].exact == "evil-pkg"


class TestRuleMatching:
    def test_scope_filter(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\nevil-pkg\n"
            "[block scope=pypi]\nevil-pkg\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        match = rs.match("npm", "evil-pkg")
        assert match is not None
        assert match.rule.scope == "npm"

    def test_method_filter(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=url methods=DELETE,POST]\ndangerous.com\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("url", "https://dangerous.com/api", method="GET") is None
        assert rs.match("url", "https://dangerous.com/api", method="DELETE") is not None
        assert rs.match("url", "https://dangerous.com/api", method="POST") is not None

    def test_first_match_wins(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[block scope=npm]\nlodash\n"
            "[allow scope=npm]\nlodash\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        match = rs.match("npm", "lodash")
        assert match is not None
        assert match.rule.action == "block"

    def test_exact_match_case_insensitive(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=npm]\nevil-pkg\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("npm", "EVIL-PKG") is not None
        assert rs.match("npm", "Evil-Pkg") is not None

    def test_regex_match(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=npm]\n/evil-.*/\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("npm", "evil-something") is not None
        assert rs.match("npm", "good-something") is None

    def test_no_match_returns_none(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=npm]\nevil-pkg\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("npm", "safe-pkg") is None

    def test_url_exact_matches_hostname(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=url]\nevil.com\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("url", "https://evil.com/payload") is not None
        assert rs.match("url", "https://good.com/page") is None

    def test_url_regex_matches_full_url(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=url]\n/api\\.evil\\.com\\/secret/\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.match("url", "https://api.evil.com/secret/data") is not None
        assert rs.match("url", "https://api.evil.com/public") is None

    def test_method_none_matches_all(self, tmp_path: Path) -> None:
        """When method is None, rules with methods filter still match."""
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[block scope=url methods=DELETE]\nevil.com\n")
        rs = RuleSet.load(rules_file, tmp_path)
        # method=None should match (no filtering)
        assert rs.match("url", "https://evil.com/api", method=None) is not None


class TestAllowlistedNames:
    def test_exact_allow_names_collected(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text(
            "[allow scope=npm]\nlodash\nexpress\n"
            "[block scope=npm]\nevil\n"
            "[allow scope=pypi]\nrequests\n"
        )
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.allowlisted_names("npm") == frozenset({"lodash", "express"})
        assert rs.allowlisted_names("pypi") == frozenset({"requests"})
        assert rs.allowlisted_names("url") == frozenset()

    def test_regex_allow_not_in_allowlisted_names(self, tmp_path: Path) -> None:
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("[allow scope=npm]\n/lodash.*/\n")
        rs = RuleSet.load(rules_file, tmp_path)
        assert rs.allowlisted_names("npm") == frozenset()


class TestNpmRulesCheck:
    async def test_block_match(self, ruleset: RuleSet) -> None:
        check = NpmRulesCheck(ruleset=ruleset)
        result = await check.run("evil-package", CheckContext())
        assert result.status.value == "fail"
        assert "block" in result.reason

    async def test_allow_match(self, ruleset: RuleSet) -> None:
        check = NpmRulesCheck(ruleset=ruleset)
        result = await check.run("lodash", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is True

    async def test_no_match(self, ruleset: RuleSet) -> None:
        check = NpmRulesCheck(ruleset=ruleset)
        result = await check.run("unknown-pkg", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is False


class TestPypiRulesCheck:
    async def test_block_match(self, ruleset: RuleSet) -> None:
        check = PypiRulesCheck(ruleset=ruleset)
        result = await check.run("evil-package", CheckContext())
        assert result.status.value == "fail"

    async def test_allow_match(self, ruleset: RuleSet) -> None:
        check = PypiRulesCheck(ruleset=ruleset)
        result = await check.run("requests", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is True

    async def test_no_match(self, ruleset: RuleSet) -> None:
        check = PypiRulesCheck(ruleset=ruleset)
        result = await check.run("unknown-pkg", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is False


class TestUrlRulesCheck:
    async def test_block_match(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://evil.example.com/payload", CheckContext())
        assert result.status.value == "fail"

    async def test_allow_match(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://github.com/repo", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is True

    async def test_no_match(self, ruleset: RuleSet) -> None:
        check = UrlRulesCheck(ruleset=ruleset)
        result = await check.run("https://unknown.com/page", CheckContext())
        assert result.status.value == "ok"
        assert result.data["allowlisted"] is False
