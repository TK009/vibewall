from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.text import Text

from vibewall.models import CheckResult, CheckStatus, RunResult
from vibewall.notifications import Notifier
from vibewall.prompter import InteractivePrompter

# Scope-dependent target column widths, TODO: calculate based on number of checks to match the last return code and time
_TARGET_WIDTH: dict[str, int] = {"npm": 24, "url": 44, "pypi": 24}

# Status → 4-char cell text
_STATUS_CELL: dict[CheckStatus, str] = {
    CheckStatus.OK: "  OK",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.SUS: " SUS",
    CheckStatus.ERR: " ERR",
}

# Status → rich style
_STATUS_STYLE: dict[CheckStatus, str] = {
    CheckStatus.OK: "green",
    CheckStatus.FAIL: "bold red",
    CheckStatus.SUS: "yellow",
    CheckStatus.ERR: "magenta",
}

_CELL_WIDTH = 5  # 4 chars + 1 space separator
_PENDING_CELL = "  ··"
_SKIPPED_CELL = "   —"
_STATUS_CODE_WIDTH = 5  # "  200", "  403", "  ···"
_LEGEND_INTERVAL = 30  # re-print column headers every N lines (approx terminal height)


def _prefix_width(scope: str) -> int:
    """Chars before the first check cell: icon(1) + ' scope '(6) + target(W) + ' '(1)."""
    return 8 + _TARGET_WIDTH.get(scope, 14)


@dataclass
class _ActiveRequest:
    scope: str
    target: str
    start_time: float
    cells: dict[str, CheckResult | None] = field(default_factory=dict)
    run_result: RunResult | None = None
    status_code: int | None = None


class ConsoleDisplay:
    def __init__(
        self,
        enabled_checks: dict[str, list[str]],
        check_abbrevs: dict[str, str],
        scope_order: dict[str, list[str]],
        verbose: bool = False,
        notifier: Notifier | None = None,
    ) -> None:
        """
        enabled_checks: {"npm": ["npm_blocklist", ...], "url": ["url_blocklist", ...]}
        check_abbrevs: maps check name → abbreviation for column headers
        scope_order: maps scope → ordered list of all check names in that scope
        """
        self._enabled = enabled_checks
        self._check_abbrevs = check_abbrevs
        self._verbose = verbose
        self._console = Console(highlight=False)
        self._is_tty = self._console.is_terminal
        self._live: Live | None = None
        self._lock = threading.Lock()
        self._active: dict[str, _ActiveRequest] = {}
        self._prompter = InteractivePrompter(
            console=self._console,
            pause_live=self.pause_live,
            resume_live=self.resume_live,
            get_active_lines=self.get_active_lines,
            notifier=notifier,
        )

        # Stats
        self._allowed = 0
        self._blocked = 0
        self._errors = 0

        # Legend repeat counter
        self._lines_since_legend: int = 0

        # When True, finished lines are buffered instead of printed
        self._prompting = False
        self._buffered_lines: list[Text] = []

        # Build ordered columns per scope (only enabled ones)
        self._columns: dict[str, list[str]] = {}
        for scope, order in scope_order.items():
            self._columns[scope] = [
                c for c in order if c in enabled_checks.get(scope, [])
            ]

    def start(self) -> None:
        """Print startup banner and start Live region."""
        self._console.print(f"\n[bold]vibewall[/bold] v0.1.0 on :{self._port_hint()}")
        self._print_legend()
        self._console.print("─" * self._console.width, style="dim")

        if self._is_tty:
            self._live = Live(
                Text(""),
                console=self._console,
                refresh_per_second=1,
                transient=True,
            )
            self._live.start()

    def begin_request(self, scope: str, target: str) -> str:
        """Register a new active request. Returns request_id."""
        req_id = uuid.uuid4().hex[:8]
        with self._lock:
            self._active[req_id] = _ActiveRequest(
                scope=scope,
                target=target,
                start_time=time.monotonic(),
                cells={c: None for c in self._columns.get(scope, [])},
            )
            self._refresh_live()
        return req_id

    def update_check(
        self, request_id: str, check_name: str, result: CheckResult | None
    ) -> None:
        """Fill in one cell for an active request."""
        with self._lock:
            req = self._active.get(request_id)
            if req is None:
                return
            req.cells[check_name] = result
            self._refresh_live()

    def set_run_result(self, request_id: str, run_result: RunResult) -> None:
        """Store the completed run result without finalizing the line."""
        with self._lock:
            req = self._active.get(request_id)
            if req is None:
                return
            req.run_result = run_result
            self._refresh_live()

    def update_status_code(self, request_id: str, code: int) -> None:
        """Set the HTTP status code for a request."""
        with self._lock:
            req = self._active.get(request_id)
            if req is None:
                return
            req.status_code = code
            self._refresh_live()

    def finish_request(self, request_id: str) -> None:
        """Move completed request from live region to scrollback."""
        with self._lock:
            req = self._active.pop(request_id, None)
            if req is None:
                return

            run_result = req.run_result
            if run_result is None:
                return

            elapsed_ms = (time.monotonic() - req.start_time) * 1000

            # Update stats
            if run_result.allowed:
                self._allowed += 1
            else:
                self._blocked += 1
            for _, cr in run_result.results:
                if cr.status == CheckStatus.ERR:
                    self._errors += 1
                    break

            # Build the set of checks that actually ran
            ran_checks = {name for name, _ in run_result.results}

            line = self._build_completed_line(req, run_result, ran_checks, elapsed_ms)

            if self._prompting:
                self._buffered_lines.append(line)
            else:
                self._console.print(line)
                self._lines_since_legend += 1

                if self._lines_since_legend >= _LEGEND_INTERVAL:
                    self._print_legend()
                    self._lines_since_legend = 0

            self._refresh_live()

    def print_stats(self) -> None:
        """Print shutdown summary."""
        if self._live is not None:
            self._live.stop()
            self._live = None

        parts = []
        parts.append(f"[green]{self._allowed} allowed[/green]")
        parts.append(f"[red]{self._blocked} blocked[/red]")
        if self._errors:
            parts.append(
                f"[magenta]{self._errors} error{'s' if self._errors != 1 else ''}[/magenta]"
            )
        summary = " · ".join(parts)
        self._console.print(f"\n── {summary} ──")

    def log(self, level: str, message: str, **kwargs: object) -> None:
        """Print a general log message."""
        style_map = {
            "warning": "yellow",
            "error": "red",
            "info": "blue",
            "debug": "dim",
        }
        style = style_map.get(level, "")
        extra = " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
        text = f"[{style}]{level.upper():>5}[/{style}] {message}"
        if extra:
            text += f" [dim]{extra}[/dim]"
        self._console.print(text)

    async def prompt_ask(
        self, check_name: str, target: str, result: CheckResult
    ) -> bool:
        """Delegate interactive prompting to the InteractivePrompter."""
        return await self._prompter.prompt_ask(check_name, target, result)

    def pause_live(self) -> None:
        """Stop the Live display (e.g. before an interactive prompt)."""
        with self._lock:
            self._prompting = True
        if self._live is not None:
            self._live.stop()

    def resume_live(self) -> None:
        """Restart the Live display (e.g. after an interactive prompt)."""
        with self._lock:
            self._prompting = False
            buffered = self._buffered_lines[:]
            self._buffered_lines.clear()
        # Flush buffered lines before restarting live region
        for line in buffered:
            self._console.print(line)
            self._lines_since_legend += 1
            if self._lines_since_legend >= _LEGEND_INTERVAL:
                self._print_legend()
                self._lines_since_legend = 0
        if self._live is not None:
            self._live.start()

    def get_active_lines(self) -> list[Text]:
        """Return display lines for all active (in-progress) requests."""
        with self._lock:
            return [self._build_active_line(req) for req in self._active.values()]

    def set_port(self, port: int) -> None:
        """Set the port for the startup banner (called before start)."""
        self._port = port

    def _port_hint(self) -> str:
        return str(getattr(self, "_port", 7777))

    def _print_legend(self) -> None:
        """Print per-scope legend lines. Each scope is its own row."""
        for scope in ("npm", "url", "pypi"):
            cols = self._columns.get(scope, [])
            if not cols:
                continue

            pw = _prefix_width(scope)
            pad = " " * pw

            # Abbreviation header line
            abbrev_line = Text(pad)
            for col_name in cols:
                abbrev = self._check_abbrevs.get(col_name, col_name[:3].upper())
                abbrev_line.append(f"{abbrev:>4} ", style="dim bold")
            self._console.print(abbrev_line)

            # Scope underline
            scope_width = len(cols) * _CELL_WIDTH + _STATUS_CODE_WIDTH
            label = f" {scope} "
            dashes_total = scope_width - len(label)
            left = dashes_total // 2
            right = dashes_total - left
            scope_line = Text(pad)
            scope_line.append("─" * left + label + "─" * right, style="dim")
            self._console.print(scope_line)

    def _build_completed_line(
        self,
        req: _ActiveRequest,
        run_result: RunResult,
        ran_checks: set[str],
        elapsed_ms: float,
    ) -> Text:
        """Build the completed request display line."""
        icon = "✓" if run_result.allowed else "✗"
        icon_style = "green" if run_result.allowed else "bold red"

        target_display = self._format_target(req.scope, req.target)
        max_target_w = _TARGET_WIDTH.get(req.scope, 14)

        line = Text()
        line.append(icon, style=icon_style)
        line.append(f" {req.scope:<4} ", style="bold")

        cols = self._columns.get(req.scope, [])
        if cols:
            if len(target_display) > max_target_w:
                target_display = target_display[: max_target_w - 1] + "…"
            line.append(f"{target_display:<{max_target_w}} ", style="")

            # Cell columns
            for col_name in cols:
                result = None
                for name, cr in run_result.results:
                    if name == col_name:
                        result = cr
                        break

                if result is not None:
                    cell_text = _STATUS_CELL.get(result.status, " ???")
                    cell_style = _STATUS_STYLE.get(result.status, "")
                    line.append(f"{cell_text} ", style=cell_style)
                elif col_name in ran_checks:
                    line.append(f"{_SKIPPED_CELL} ", style="dim")
                else:
                    line.append(f"{_SKIPPED_CELL} ", style="dim")

            # Status code
            line.append(self._format_status_code(req.status_code))
        else:
            line.append(target_display, style="")

        # Elapsed time
        line.append(f" {elapsed_ms:>5.0f}ms", style="dim")

        # Reason / warnings / errors on the same line
        if run_result.blocked:
            # Blocked: fail reason is most important
            line.append(f"  {run_result.reason}", style="red")
            # Show errors after fail reason (fail-close: fail > error)
            for err in run_result.errors:
                line.append(f"  {err}", style="magenta")
        else:
            # Allowed: show errors first (fail-open: error is notable),
            # then warnings
            for err in run_result.errors:
                line.append(f"  {err}", style="magenta")
            for warn in run_result.warnings:
                line.append(f"  {warn}", style="yellow")

            # Fallback: if no messages were shown but there are non-OK
            # results, show the worst one so the user always sees a reason
            if not run_result.errors and not run_result.warnings:
                worst = self._worst_result(run_result)
                if worst is not None:
                    style = _STATUS_STYLE.get(worst.status, "")
                    line.append(f"  {worst.reason}", style=style)

        return line

    def _build_active_line(self, req: _ActiveRequest) -> Text:
        """Build a single-line display for an active (in-progress) request."""
        target_display = self._format_target(req.scope, req.target)
        max_target_w = _TARGET_WIDTH.get(req.scope, 14)

        line = Text()
        line.append("▸ ", style="bold yellow")
        line.append(f"{req.scope:<4} ", style="bold")

        cols = self._columns.get(req.scope, [])
        if cols:
            if len(target_display) > max_target_w:
                target_display = target_display[: max_target_w - 1] + "…"
            line.append(f"{target_display:<{max_target_w}} ", style="")

            for col_name in cols:
                result = req.cells.get(col_name)
                if result is not None:
                    cell_text = _STATUS_CELL.get(result.status, " ???")
                    cell_style = _STATUS_STYLE.get(result.status, "")
                    line.append(f"{cell_text} ", style=cell_style)
                else:
                    line.append(f"{_PENDING_CELL} ", style="dim")

            # Status code placeholder
            if req.status_code is not None:
                line.append(self._format_status_code(req.status_code))
            else:
                line.append(f"{'···':>5}", style="dim")
        else:
            line.append(target_display, style="")

        return line

    def _format_status_code(self, code: int | None) -> Text:
        """Format an HTTP status code as a 5-char Text fragment."""
        t = Text()
        if code is None:
            t.append(f"{'···':>5}", style="dim")
        elif 200 <= code < 300:
            t.append(f"{code:>5}", style="green")
        elif 300 <= code < 400:
            t.append(f"{code:>5}", style="yellow")
        else:
            t.append(f"{code:>5}", style="red")
        return t

    def _refresh_live(self) -> None:
        """Update the Live region with all active requests."""
        if not self._is_tty or self._live is None or self._prompting:
            return

        if not self._active:
            self._live.update(Text(""))
            self._live.refresh()
            return

        combined = Text()
        for i, req in enumerate(list(self._active.values())):
            if i > 0:
                combined.append("\n")
            combined.append_text(self._build_active_line(req))

        self._live.update(combined)
        self._live.refresh()

    @staticmethod
    def _worst_result(run_result: RunResult) -> CheckResult | None:
        """Return the most severe non-OK result, or None if all OK."""
        _SEVERITY = {
            CheckStatus.OK: 0,
            CheckStatus.ERR: 1,
            CheckStatus.SUS: 2,
            CheckStatus.FAIL: 3,
        }
        worst: CheckResult | None = None
        for _, cr in run_result.results:
            if cr.status == CheckStatus.OK:
                continue
            if worst is None or _SEVERITY.get(cr.status, 0) > _SEVERITY.get(
                worst.status, 0
            ):
                worst = cr
        return worst

    def _format_target(self, scope: str, target: str) -> str:
        """Format target for display. npm shows package name, url shows URL."""
        if scope == "url":
            # Strip protocol to save space
            for prefix in ("https://", "http://"):
                if target.startswith(prefix):
                    target = target[len(prefix) :]
                    break
        return target
