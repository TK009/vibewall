"""Tests for shared OSV helpers."""

from __future__ import annotations

from vibewall.validators.checks._osv import affects_version


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
