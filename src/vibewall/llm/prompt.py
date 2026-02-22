from __future__ import annotations

from typing import TYPE_CHECKING

from vibewall.models import CheckResult

if TYPE_CHECKING:
    from vibewall.llm.history import HistoryEntry

_SYSTEM_PROMPT = """\
You are a security reviewer for a software supply-chain firewall. Your job is \
to decide whether a package install or URL request should be ALLOWED, BLOCKED, \
or treated as a WARNING based on the automated check results provided.

Respond with EXACTLY this format on the FIRST line:
DECISION: ALLOW|BLOCK|WARN

Then provide a brief explanation on subsequent lines.

Guidelines:
- BLOCK when checks indicate clear risk (malicious, typosquat, non-existent, very new with no downloads)
- WARN when checks are inconclusive or mildly suspicious
- ALLOW when checks show the target is safe or only has minor issues
- Consider the recent request history for context (e.g. if many suspicious packages are being installed in sequence)
"""


def build_llm_prompt(
    scope: str,
    target: str,
    check_results: list[tuple[str, CheckResult]],
    history: list[HistoryEntry] | None = None,
) -> tuple[str, str]:
    lines = [f"Scope: {scope}", f"Target: {target}", "", "Check results:"]
    for name, result in check_results:
        lines.append(f"  {name}: {result.status.value} — {result.reason}")

    if history:
        lines.append("")
        lines.append("Recent request history:")
        for entry in history:
            statuses = ", ".join(
                f"{n}={r.status.value}" for n, r in entry.results
            )
            lines.append(f"  [{entry.scope}] {entry.target} → {entry.outcome} ({statuses})")

    user_prompt = "\n".join(lines)
    return _SYSTEM_PROMPT, user_prompt
