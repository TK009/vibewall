from __future__ import annotations

from vibewall.cache.serde import deserialize, serialize
from vibewall.models import CheckResult, CheckStatus


class TestSerdeRoundTrip:
    def test_check_result_ok(self) -> None:
        cr = CheckResult.ok("all good", foo="bar")
        raw = serialize(cr)
        restored = deserialize(raw)
        assert isinstance(restored, CheckResult)
        assert restored.status == CheckStatus.OK
        assert restored.reason == "all good"
        assert restored.data == {"foo": "bar"}

    def test_check_result_fail(self) -> None:
        cr = CheckResult.fail("bad", score=42)
        raw = serialize(cr)
        restored = deserialize(raw)
        assert restored.status == CheckStatus.FAIL
        assert restored.reason == "bad"
        assert restored.data["score"] == 42

    def test_check_result_err(self) -> None:
        cr = CheckResult.err("timeout")
        raw = serialize(cr)
        restored = deserialize(raw)
        assert restored.status == CheckStatus.ERR
        assert restored.reason == "timeout"

    def test_check_result_sus(self) -> None:
        cr = CheckResult.sus("sketchy", level=3)
        raw = serialize(cr)
        restored = deserialize(raw)
        assert restored.status == CheckStatus.SUS
        assert restored.data["level"] == 3

    def test_tuple_of_check_results(self) -> None:
        raw_cr = CheckResult.ok("ok")
        display_cr = CheckResult.sus("downgraded")
        pair = (raw_cr, display_cr)
        serialized = serialize(pair)
        restored = deserialize(serialized)
        assert isinstance(restored, tuple)
        assert len(restored) == 2
        assert isinstance(restored[0], CheckResult)
        assert isinstance(restored[1], CheckResult)
        assert restored[0].status == CheckStatus.OK
        assert restored[1].status == CheckStatus.SUS

    def test_plain_string(self) -> None:
        raw = serialize("hello")
        assert deserialize(raw) == "hello"

    def test_plain_dict(self) -> None:
        d = {"key": "value", "num": 123}
        raw = serialize(d)
        assert deserialize(raw) == d

    def test_none(self) -> None:
        raw = serialize(None)
        assert deserialize(raw) is None
