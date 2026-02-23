"""Tests for shared OSV helpers."""

from __future__ import annotations

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
    def test_critical(self) -> None:
        assert cvss_to_severity(9.0) == "CRITICAL"
        assert cvss_to_severity(10.0) == "CRITICAL"

    def test_high(self) -> None:
        assert cvss_to_severity(7.0) == "HIGH"
        assert cvss_to_severity(8.9) == "HIGH"

    def test_moderate(self) -> None:
        assert cvss_to_severity(4.0) == "MODERATE"
        assert cvss_to_severity(6.9) == "MODERATE"

    def test_low(self) -> None:
        assert cvss_to_severity(0.0) == "LOW"
        assert cvss_to_severity(3.9) == "LOW"


class TestExtractSeverity:
    def test_database_specific_severity(self) -> None:
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert extract_severity(vuln) == "CRITICAL"

    def test_database_specific_case_insensitive(self) -> None:
        vuln = {"database_specific": {"severity": "high"}}
        assert extract_severity(vuln) == "HIGH"

    def test_cvss_v3_plain_score(self) -> None:
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert extract_severity(vuln) == "CRITICAL"

    def test_cvss_v3_vector_string_falls_through(self) -> None:
        """CVSS vector strings contain the spec version (3.1), not a score.
        They must not be parsed as a numeric score."""
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
        # No database_specific.severity, vector can't be parsed → fallback HIGH
        assert extract_severity(vuln) == "HIGH"

    def test_cvss_v3_vector_with_database_severity(self) -> None:
        """When database_specific.severity exists, vector string is irrelevant."""
        vuln = {
            "database_specific": {"severity": "CRITICAL"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N"}],
        }
        assert extract_severity(vuln) == "CRITICAL"

    def test_fallback_to_high(self) -> None:
        vuln = {}
        assert extract_severity(vuln) == "HIGH"

    def test_invalid_database_severity_falls_through(self) -> None:
        vuln = {"database_specific": {"severity": "UNKNOWN"}}
        assert extract_severity(vuln) == "HIGH"


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
