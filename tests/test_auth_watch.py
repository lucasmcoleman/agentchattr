"""Login-expired detection: one alert per expiry, no alerts for quoted prose."""
import unittest

from auth_watch import AuthExpiryWatch, alert_text

# Screen captured from claudework on LUCAS-PC, 2026-11-06 22:10 (glyphs as read).
EXPIRED = """\
> use mcp to read #general - you're mentioned, take appropriate action and respond

⎿  Login expired · Please run /login

✳ Baked for 0s · done 10:09 PM
                                                       Not logged in · Run /login
>
"""
QUOTED = """\
- **claudework:** every mention got "Login expired · Please run /login" and ended in 0 s.
I'll add a detector for Login expired · Please run /login lines.
"""


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class AuthWatchTests(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self.clock = Clock()
        self.watch = AuthExpiryWatch(lambda: self.sent.append(1), cooldown=1800, clock=self.clock)

    def test_real_screen_alerts_once(self):
        self.assertTrue(self.watch.observe(EXPIRED))
        self.assertFalse(self.watch.observe(EXPIRED))  # same screen, no new line
        self.assertEqual(len(self.sent), 1)

    def test_more_failed_prompts_within_cooldown_stay_quiet(self):
        self.watch.observe(EXPIRED)
        self.clock.t += 60
        self.assertFalse(self.watch.observe(EXPIRED + "\n⎿  Login expired · Please run /login\n"))
        self.assertEqual(len(self.sent), 1)

    def test_new_expiry_after_cooldown_alerts_again(self):
        self.watch.observe(EXPIRED)
        self.watch.observe("> all good\n")  # login fixed, lines scrolled away
        self.clock.t += 1801
        self.assertTrue(self.watch.observe(EXPIRED))
        self.assertEqual(len(self.sent), 2)

    def test_quoted_prose_does_not_alert(self):
        self.assertFalse(self.watch.observe(QUOTED))
        self.assertEqual(self.sent, [])

    def test_empty_and_none_are_safe(self):
        self.assertFalse(self.watch.observe(""))
        self.assertFalse(self.watch.observe(None))

    def test_failed_delivery_retries_while_still_expired(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise OSError("server down")
        watch = AuthExpiryWatch(flaky, cooldown=1800, retry_after=60, clock=self.clock)
        self.assertFalse(watch.observe(EXPIRED))   # send failed: not reported as alerted
        self.clock.t += 30
        self.assertFalse(watch.observe(EXPIRED))   # waits for retry_after
        self.clock.t += 31
        self.assertTrue(watch.observe(EXPIRED))    # retried and delivered
        self.clock.t += 61
        self.assertFalse(watch.observe(EXPIRED))   # delivered: back to the cooldown
        self.assertEqual(len(calls), 2)

    def test_failed_delivery_stops_retrying_once_login_fixed(self):
        calls = []

        def down():
            calls.append(1)
            raise OSError("server down")
        watch = AuthExpiryWatch(down, retry_after=60, clock=self.clock)
        watch.observe(EXPIRED)
        watch.observe("> all good\n")
        self.clock.t += 120
        self.assertFalse(watch.observe("> all good\n"))
        self.assertEqual(len(calls), 1)

    def test_alert_text_tags_lucas_and_names_fix(self):
        text = alert_text("claudework", "LUCAS-PC")
        self.assertTrue(text.startswith("@Lucas claudework on LUCAS-PC"))
        self.assertIn("/login", text)


if __name__ == "__main__":
    unittest.main()
