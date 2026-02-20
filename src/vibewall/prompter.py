from __future__ import annotations

import asyncio
import sys
import termios
import tty
from collections.abc import Callable

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vibewall.models import CheckResult

# Severity → Rich style for advisory display
_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MODERATE": "yellow",
    "MEDIUM": "yellow",
    "LOW": "dim",
}


def _read_single_key() -> str:
    """Read a single keypress from stdin without waiting for Enter."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        # Ctrl-C in raw mode comes through as \x03
        if ch == "\x03":
            raise KeyboardInterrupt
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


class InteractivePrompter:
    """Handles interactive TTY prompts for ask-mode checks."""

    def __init__(
        self,
        console: Console,
        pause_live: Callable[[], None],
        resume_live: Callable[[], None],
        get_active_lines: Callable[[], list[Text]],
    ) -> None:
        self._console = console
        self._pause_live = pause_live
        self._resume_live = resume_live
        self._get_active_lines = get_active_lines
        self._ask_lock = asyncio.Lock()

    async def prompt_ask(self, check_name: str, target: str, result: CheckResult) -> bool:
        """Interactively prompt the user to approve or deny a failing check.

        Returns True if user approves (y/Y), False otherwise.
        """
        async with self._ask_lock:
            self._pause_live()

            try:
                # Print a snapshot of all active requests so the user
                # can see the current state of in-flight checks.
                active_lines = self._get_active_lines()
                if active_lines:
                    self._console.print()
                    for line in active_lines:
                        self._console.print(line)

                body = Text()
                body.append("Check:  ", style="bold")
                body.append(f"{check_name}\n")
                body.append("Target: ", style="bold")
                body.append(f"{target}\n")
                body.append("Reason: ", style="bold")
                body.append(f"{result.reason}\n")
                if result.data:
                    advisories = result.data.get("advisories")
                    if advisories and isinstance(advisories, list):
                        body.append("\n")
                        for adv in advisories:
                            sev = adv.get("severity", "UNKNOWN").upper()
                            sev_style = _SEVERITY_STYLE.get(sev, "")
                            vuln_id = adv.get("id", "unknown")
                            summary = adv.get("summary", "")
                            details = adv.get("details", "")
                            body.append(f"  [{sev}]", style=sev_style)
                            body.append(f" {vuln_id}", style="bold")
                            if summary:
                                body.append(f" — {summary}", style="dim")
                            body.append("\n")
                            if details:
                                # Show first paragraph, trimmed
                                first_para = details.strip().split("\n\n")[0]
                                first_para = first_para.replace("\n", " ").strip()
                                if len(first_para) > 600:
                                    first_para = first_para[:597] + "..."
                                body.append(f"    {first_para}\n", style="dim")
                    # Show any other data keys (excluding internal ones)
                    for key, value in result.data.items():
                        if key in ("action_override", "advisories"):
                            continue
                        body.append(f"  {key}: ", style="dim")
                        body.append(f"{value}\n")

                panel = Panel(
                    body,
                    title="[bold yellow]vibewall ask[/bold yellow]",
                    border_style="yellow",
                    expand=False,
                )
                self._console.print(panel)
                self._console.print("[bold yellow]Allow this request? (Y/n):[/bold yellow] ", end="")

                loop = asyncio.get_running_loop()
                try:
                    ch = await loop.run_in_executor(None, _read_single_key)
                except (KeyboardInterrupt, EOFError):
                    self._console.print()  # newline after ^C
                    return False
                approved = ch.lower() != "n"
                label = "yes" if approved else "no"
                style = "green" if approved else "red"
                self._console.print(f"[{style}]{label}[/{style}]")
                return approved
            finally:
                self._resume_live()
