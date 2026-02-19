from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from rich.console import Console
from rich.live import Live
from rich.text import Text

from vibewall.models import CheckResult, CheckStatus, RunResult

# Maps check names → 3-char column abbreviations
_CHECK_ABBREV: dict[str, str] = {
    "npm_blocklist": "BLK",
    "npm_allowlist": "ALW",
    "npm_registry": "REG",
    "npm_existence": "EXI",
    "npm_typosquat": "TYP",
    "npm_age": "AGE",
    "npm_downloads": " DL",
    "url_blocklist": "BLK",
    "url_allowlist": "ALW",
    "url_dns": "DNS",
    "url_domain_age": "AGE",
}

# Canonical column order per scope
_SCOPE_ORDER: dict[str, list[str]] = {
    "npm": [
        "npm_blocklist", "npm_allowlist", "npm_registry",
        "npm_existence", "npm_typosquat", "npm_age", "npm_downloads",
    ],
    "url": [
        "url_blocklist", "url_allowlist", "url_dns", "url_domain_age",
    ],
}

# Status → 4-char cell text
_STATUS_CELL: dict[CheckStatus, str] = {
    CheckStatus.OK:   "  OK",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.SUS:  " SUS",
    CheckStatus.ERR:  " ERR",
}

# Status → rich style
_STATUS_STYLE: dict[CheckStatus, str] = {
    CheckStatus.OK:   "green",
    CheckStatus.FAIL: "bold red",
    CheckStatus.SUS:  "yellow",
    CheckStatus.ERR:  "magenta",
}

_CELL_WIDTH = 5  # 4 chars + 1 space separator
_PENDING_CELL = "  ··"
_SKIPPED_CELL = "   —"


@dataclass
class _ActiveRequest:
    scope: str
    target: str
    start_time: float
    cells: dict[str, CheckResult | None] = field(default_factory=dict)


class ConsoleDisplay:
    def __init__(
        self,
        enabled_checks: dict[str, list[str]],
        verbose: bool = False,
    ) -> None:
        """
        enabled_checks: {"npm": ["npm_blocklist", ...], "url": ["url_blocklist", ...]}
        """
        self._enabled = enabled_checks
        self._verbose = verbose
        self._console = Console(highlight=False)
        self._is_tty = self._console.is_terminal
        self._live: Live | None = None
        self._lock = threading.Lock()
        self._active: dict[str, _ActiveRequest] = {}

        # Stats
        self._allowed = 0
        self._blocked = 0
        self._errors = 0

        # Build ordered columns per scope (only enabled ones)
        self._columns: dict[str, list[str]] = {}
        for scope, order in _SCOPE_ORDER.items():
            self._columns[scope] = [c for c in order if c in enabled_checks.get(scope, [])]

    def start(self) -> None:
        """Print startup banner and start Live region."""
        self._console.print(f"\n[bold]vibewall[/bold] v0.1.0 on :{self._port_hint()}")

        # Validator column headers
        header = Text("validators: ")
        scope_line = Text("            ")
        any_cols = False
        for scope in ("npm", "url"):
            cols = self._columns.get(scope, [])
            if not cols:
                continue
            if any_cols:
                header.append(" | ", style="dim")
                scope_line.append("   ", style="dim")
            for col_name in cols:
                abbrev = _CHECK_ABBREV.get(col_name, col_name[:3].upper())
                header.append(f"{abbrev:>4} ", style="dim bold")
            scope_width = len(cols) * _CELL_WIDTH
            label = f" {scope} "
            dashes_total = scope_width - len(label)
            left = dashes_total // 2
            right = dashes_total - left
            scope_line.append("─" * left + label + "─" * right + " ", style="dim")
            any_cols = True

        if any_cols:
            self._console.print(header)
            self._console.print(scope_line)

        self._console.print("─" * self._console.width, style="dim")

        if self._is_tty:
            self._live = Live(
                Text(""),
                console=self._console,
                refresh_per_second=8,
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

    def update_check(self, request_id: str, check_name: str, result: CheckResult | None) -> None:
        """Fill in one cell for an active request."""
        with self._lock:
            req = self._active.get(request_id)
            if req is None:
                return
            req.cells[check_name] = result
            self._refresh_live()

    def finish_request(self, request_id: str, run_result: RunResult) -> None:
        """Move completed request from live region to scrollback."""
        with self._lock:
            req = self._active.pop(request_id, None)
            if req is None:
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

            if self._is_tty and self._live is not None:
                self._console.print(line)
            else:
                self._console.print(line)

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
            parts.append(f"[magenta]{self._errors} error{'s' if self._errors != 1 else ''}[/magenta]")
        summary = " · ".join(parts)
        self._console.print(f"\n── {summary} ──")

    def log(self, level: str, message: str, **kwargs: object) -> None:
        """Print a general log message."""
        style_map = {"warning": "yellow", "error": "red", "info": "blue", "debug": "dim"}
        style = style_map.get(level, "")
        extra = " ".join(f"{k}={v}" for k, v in kwargs.items()) if kwargs else ""
        text = f"[{style}]{level.upper():>5}[/{style}] {message}"
        if extra:
            text += f" [dim]{extra}[/dim]"
        if self._is_tty and self._live is not None:
            self._console.print(text)
        else:
            self._console.print(text)

    def set_port(self, port: int) -> None:
        """Set the port for the startup banner (called before start)."""
        self._port = port

    def _port_hint(self) -> str:
        return str(getattr(self, "_port", 7777))

    def _build_completed_line(
        self,
        req: _ActiveRequest,
        run_result: RunResult,
        ran_checks: set[str],
        elapsed_ms: float,
    ) -> Text:
        """Build the completed request display line(s)."""
        icon = "✓" if run_result.allowed else "✗"
        icon_style = "green" if run_result.allowed else "bold red"

        target_display = self._format_target(req.scope, req.target)

        line = Text()
        line.append(icon, style=icon_style)
        line.append(f" {req.scope:<4} ", style="bold")

        cols = self._columns.get(req.scope, [])
        if cols:
            # Target column: truncate to fit before cells
            max_target_w = 14
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
        else:
            line.append(target_display, style="")

        # Elapsed time
        line.append(f" {elapsed_ms:>5.0f}ms", style="dim")

        # Reason for blocked/failed requests
        if run_result.blocked:
            line.append(f"  {run_result.reason}", style="red")

        return line

    def _build_active_line(self, req: _ActiveRequest) -> Text:
        """Build a single-line display for an active (in-progress) request."""
        target_display = self._format_target(req.scope, req.target)

        line = Text()
        line.append("▸ ", style="bold yellow")
        line.append(f"{req.scope:<4} ", style="bold")

        cols = self._columns.get(req.scope, [])
        if cols:
            max_target_w = 14
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
        else:
            line.append(target_display, style="")

        return line

    def _refresh_live(self) -> None:
        """Update the Live region with all active requests."""
        if not self._is_tty or self._live is None:
            return

        if not self._active:
            self._live.update(Text(""))
            return

        combined = Text()
        for i, req in enumerate(self._active.values()):
            if i > 0:
                combined.append("\n")
            combined.append_text(self._build_active_line(req))

        self._live.update(combined)

    def _format_target(self, scope: str, target: str) -> str:
        """Format target for display. npm shows package name, url shows URL."""
        if scope == "npm" and not self._verbose:
            return target  # Already just the package name
        return target
