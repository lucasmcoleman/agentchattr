"""Detect an agent CLI whose login has expired, so the room can tell the human.

The wrapper's activity checker already reads the agent's visible screen once a
second. It passes that text to AuthExpiryWatch.observe(). When a new
login-expired line appears, the watch calls notify() once; further alerts wait
for the cooldown, so a burst of failed prompts produces one room message.

Patterns only match at the start of a line (after an optional status glyph),
which is how the CLIs print them. Prose that quotes the message mid-sentence
does not trigger an alert. Add new CLI wordings to AUTH_EXPIRED_LINE.
"""
import re
import time

AUTH_EXPIRED_LINE = re.compile(
    r"^[^\w/]{0,4}\s*(?:"
    r"(?:Login expired|Not logged in|OAuth token (?:has )?expired|Invalid API key)"
    r"\s*\W\s*(?:Please run|Run) /login"
    r")",
    re.MULTILINE | re.IGNORECASE,
)

DEFAULT_COOLDOWN = 30 * 60  # seconds between alerts for the same agent


class AuthExpiryWatch:
    def __init__(self, notify, *, cooldown: float = DEFAULT_COOLDOWN, clock=time.monotonic):
        self._notify = notify
        self._cooldown = cooldown
        self._clock = clock
        self._last_count = 0
        self._last_alert = None

    def observe(self, screen_text: str) -> bool:
        """Feed the visible screen. Returns True when an alert was sent."""
        count = len(AUTH_EXPIRED_LINE.findall(screen_text or ""))
        grew = count > self._last_count
        self._last_count = count
        if not grew:
            return False
        now = self._clock()
        if self._last_alert is not None and now - self._last_alert < self._cooldown:
            return False
        self._last_alert = now
        try:
            self._notify()
        except Exception:
            pass
        return True


def alert_text(agent: str, host: str) -> str:
    return (
        f"@Lucas {agent} on {host} can't answer: its CLI login has expired, so every "
        f"prompt fails until someone signs in. Fix: in the {agent} console on {host}, "
        f"type /login and finish the browser sign-in, then re-send any mentions it missed."
    )
