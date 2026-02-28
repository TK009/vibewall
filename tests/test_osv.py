"""Tests for shared OSV helpers."""

from __future__ import annotations

import pytest

from vibewall.validators.checks._osv import (
    affects_version,
    cvss_to_severity,
    extract_severity,
    has_fix,
)


class TestAffectsVersion:
    def test_no_affected_data_assumes_affected(self) -> None:
        assert affects_version({"id": "X"}, "1.0.0") is True

    def test_empty_affected_list_assumes_affected(self) -> None:
        assert affects_version({"affected": []}, "1.0.0") is True

    def test_exact_version_match(self) -> None:
        vuln = {"affected": [{"versions": ["1.0.0", "1.1.0"]}]}
        assert affects_version(vuln, "1.0.0") is True

    def test_version_not_in_list(self) -> None:
        vuln = {"affected": [{"versions": ["1.0.0", "1.1.0"]}]}
        assert affects_version(vuln, "2.0.0") is False

    def test_ranges_without_versions_assumes_affected(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        assert affects_version(vuln, "1.5.0") is True

    def test_ranges_with_versions_conservatively_assumes_affected(self) -> None:
        vuln = {
            "affected": [{
                "versions": ["1.0.0"],
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }],
        }
        # Version is in the explicit list
        assert affects_version(vuln, "1.0.0") is True
        # Version is NOT in the explicit list but ranges exist —
        # conservatively assume affected since we can't evaluate ranges
        assert affects_version(vuln, "1.5.0") is True

    def test_multiple_affected_entries(self) -> None:
        vuln = {
            "affected": [
                {"versions": ["1.0.0"]},
                {"versions": ["2.0.0"]},
            ],
        }
        assert affects_version(vuln, "2.0.0") is True
        assert affects_version(vuln, "3.0.0") is False


class TestCvssToSeverity:
    @pytest.mark.parametrize("score,expected", [
        (0.0, "LOW"),
        (3.9, "LOW"),
        (4.0, "MODERATE"),
        (6.9, "MODERATE"),
        (7.0, "HIGH"),
        (8.9, "HIGH"),
        (9.0, "CRITICAL"),
        (10.0, "CRITICAL"),
    ], ids=["low-min", "low-boundary", "moderate-min", "moderate-boundary",
            "high-min", "high-boundary", "critical-min", "critical-max"])
    def test_cvss_to_severity(self, score: float, expected: str) -> None:
        assert cvss_to_severity(score) == expected


class TestExtractSeverity:
    @pytest.mark.parametrize("vuln,expected", [
        pytest.param(
            {"database_specific": {"severity": "CRITICAL"}},
            "CRITICAL", id="database-specific"),
        pytest.param(
            {"database_specific": {"severity": "high"}},
            "HIGH", id="database-specific-case-insensitive"),
        pytest.param(
            {"severity": [{"type": "CVSS_V3", "score": "9.8"}]},
            "CRITICAL", id="cvss-v3-plain-score"),
        pytest.param(
            {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]},
            "HIGH", id="cvss-v3-vector-falls-through"),
        pytest.param(
            {"database_specific": {"severity": "CRITICAL"},
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"}]},
            "CRITICAL", id="database-severity-beats-vector"),
        pytest.param({}, "HIGH", id="fallback-to-high"),
        pytest.param(
            {"database_specific": {"severity": "UNKNOWN"}},
            "HIGH", id="invalid-database-severity-falls-through"),
    ])
    def test_extract_severity(self, vuln: dict, expected: str) -> None:
        assert extract_severity(vuln) == expected


class TestHasFix:
    def test_has_fix_true(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.2.3"},
                    ]
                }]
            }]
        }
        assert has_fix(vuln) is True

    def test_has_fix_false_no_fixed_event(self) -> None:
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                    ]
                }]
            }]
        }
        assert has_fix(vuln) is False

    def test_has_fix_false_no_affected(self) -> None:
        assert has_fix({}) is False

    def test_has_fix_false_empty_ranges(self) -> None:
        vuln = {"affected": [{"ranges": []}]}
        assert has_fix(vuln) is False
