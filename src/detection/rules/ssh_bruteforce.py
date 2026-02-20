from .base_rule import BaseRule


class SSHBruteForceRule(BaseRule):

    def __init__(self):
        super().__init__(
            "SSH_BRUTE_FORCE",
            "Multiple SSH failed login attempts detected",
            "medium",
            "T1110",
            "Credential Access"
        )

    def evaluate(self, events):
        failed = [e for e in events if "Failed password" in e.get("raw", "")]

        if len(failed) > 5:
            return [
                self.build_alert(
                    f"{len(failed)} failed SSH attempts detected",
                    event=failed[0]
                )
            ]

        return []