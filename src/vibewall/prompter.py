from __future__ import annotations

import asyncio
import sys
import termios
import tty
from collections.abc import Callable
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vibewall.models import CheckResult

if TYPE_CHECKING:
    from vibewall.notifications import Notifier

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
        notifier: Notifier | None = None,
        ask_timeout: int = 120,
    ) -> None:
        self._console = console
        self._pause_live = pause_live
        self._resume_live = resume_live
        self._get_active_lines = get_active_lines
        self._notifier = notifier
        self._ask_timeout = ask_timeout
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
                terminal_task = asyncio.ensure_future(
                    loop.run_in_executor(None, _read_single_key)
                )

                notify_task = None
                if self._notifier is not None:
                    notify_task = asyncio.create_task(
                        self._notifier.prompt_ask(check_name, target, result.reason)
                    )

                tasks: set[asyncio.Task] = {terminal_task}
                if notify_task is not None:
                    tasks.add(notify_task)

                approved: bool | None = None
                try:
                    approved = await asyncio.wait_for(
                        self._wait_for_decision(tasks, terminal_task, notify_task),
                        timeout=self._ask_timeout,
                    )
                except asyncio.TimeoutError:
                    # Overall ask timeout expired; return None to let caller
                    # fall through to the action's default (allow/block).
                    approved = None

                # Cancel any remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()

                if approved is None:
                    self._console.print("[dim]timed out[/dim]")
                    return False

                label = "yes" if approved else "no"
                style = "green" if approved else "red"
                self._console.print(f"[{style}]{label}[/{style}]")
                return approved
            finally:
                self._resume_live()

    async def _wait_for_decision(
        self,
        tasks: set[asyncio.Task],
        terminal_task: asyncio.Task,
        notify_task: asyncio.Task | None,
    ) -> bool:
        """Wait for a definitive user decision from terminal or notification.

        If the notification finishes with None (dismissed/timed out), it is
        removed from the task set and we continue waiting for terminal input.
        Only an explicit True/False from the notification counts as a decision.
        """
        while tasks:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            tasks.clear()
            tasks.update(pending)

            for winner in done:
                if winner is terminal_task:
                    try:
                        ch = winner.result()
                    except (KeyboardInterrupt, EOFError):
                        self._console.print()
                        return False
                    return ch.lower() != "n"
                else:
                    # Notification task finished
                    try:
                        notify_result = winner.result()
                    except Exception:
                        notify_result = None
                    if notify_result is not None:
                        return notify_result
                    # Notification dismissed/timed out (None) — keep waiting
                    # for terminal input

        # All tasks exhausted without a decision (shouldn't happen normally)
        return False
