from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.suspicious_login_after_bruteforce import (
    SuspiciousLoginAfterBruteForceRule,
)


def get_all_rules():
    """
    Returns all registered detection rule classes.
    """
    return [
        SSHBruteForceRule(),
        SuspiciousLoginAfterBruteForceRule(),
    ]
