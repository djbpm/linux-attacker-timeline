from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.suspicious_login_after_bruteforce import SuspiciousLoginAfterBruteForceRule


def load_rules():
    return [
        SSHBruteForceRule(),
        SuspiciousLoginAfterBruteForceRule()
    ]

