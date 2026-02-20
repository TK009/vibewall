from __future__ import annotations

from pathlib import Path

from vibewall.validators.allowlist import AllowBlockList


class TestAllowBlockListLoading:
    def test_basic_loading(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("lodash\nexpress\n")
        block = tmp_path / "block.txt"
        block.write_text("evil-pkg\n")
        lists = AllowBlockList(allow, block)
        assert lists.is_allowed("lodash")
        assert lists.is_blocked("evil-pkg")

    def test_none_paths(self) -> None:
        lists = AllowBlockList(None, None)
        assert not lists.is_allowed("anything")
        assert not lists.is_blocked("anything")

    def test_nonexistent_paths(self, tmp_path: Path) -> None:
        lists = AllowBlockList(tmp_path / "nope.txt", tmp_path / "nope2.txt")
        assert not lists.is_allowed("anything")
        assert not lists.is_blocked("anything")

    def test_empty_file(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("")
        lists = AllowBlockList(allow, None)
        assert not lists.is_allowed("anything")

    def test_comments_and_blank_lines(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("# this is a comment\n\nlodash\n  \n# another comment\nexpress\n")
        lists = AllowBlockList(allow, None)
        assert lists.is_allowed("lodash")
        assert lists.is_allowed("express")
        assert not lists.is_allowed("# this is a comment")

    def test_whitespace_stripped(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("  lodash  \n\texpress\t\n")
        lists = AllowBlockList(allow, None)
        assert lists.is_allowed("lodash")
        assert lists.is_allowed("express")


class TestCaseInsensitive:
    def test_lookup_is_case_insensitive(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("Lodash\n")
        block = tmp_path / "block.txt"
        block.write_text("Evil-Pkg\n")
        lists = AllowBlockList(allow, block)
        assert lists.is_allowed("lodash")
        assert lists.is_allowed("LODASH")
        assert lists.is_blocked("evil-pkg")
        assert lists.is_blocked("EVIL-PKG")


class TestScopedPackages:
    def test_scoped_package_names(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("@babel/core\n@scope/pkg\n")
        lists = AllowBlockList(allow, None)
        assert lists.is_allowed("@babel/core")
        assert lists.is_allowed("@scope/pkg")
        assert not lists.is_allowed("@babel/other")


class TestAllowlistProperty:
    def test_allowlist_returns_frozenset(self, tmp_path: Path) -> None:
        allow = tmp_path / "allow.txt"
        allow.write_text("lodash\nexpress\n")
        lists = AllowBlockList(allow, None)
        assert isinstance(lists.allowlist, frozenset)
        assert lists.allowlist == frozenset({"lodash", "express"})
