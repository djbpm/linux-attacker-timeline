from .base_rule import BaseRule


class SuspiciousLoginAfterBruteForceRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SUSPICIOUS_LOGIN_AFTER_BRUTEFORCE",
            "Suspicious login detected after brute force attempts",
            "high",
            "T1078",
            "Initial Access"
        )

    def evaluate(self, events):
        failed = [e for e in events if "Failed password" in e.get("raw", "")]
        success = [e for e in events if "Accepted password" in e.get("raw", "")]

        if len(failed) > 5 and len(success) >= 1:
            # use the first successful login event as reference
            reference_event = success[0]

            return [
                self.build_alert(
                    evidence="Login occurred after multiple failed attempts",
                    event=reference_event,
                    confidence="high"
                )
            ]

        return []