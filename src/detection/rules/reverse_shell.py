from .base_rule import BaseRule


class ReverseShellRule(BaseRule):

    def __init__(self):
        super().__init__(
            "REVERSE_SHELL",
            "Reverse shell execution detected",
            "high",
            "T1059",
            "Execution"
        )

    def evaluate(self, events):
        matches = [e for e in events if "/dev/tcp/" in e.get("raw", "")]

        if matches:
            return [
                self.build_alert(
                    matches[0].get("raw"),
                    event=matches[0]
                )
            ]

        return []