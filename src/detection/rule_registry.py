from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.suspicious_login_after_bruteforce import SuspiciousLoginAfterBruteForceRule
from src.detection.rules.privilege_escalation_sudo import SudoPrivilegeEscalationRule


def get_all_rules():
    return [
        SSHBruteForceRule(),
        SuspiciousLoginAfterBruteForceRule(),
        SudoPrivilegeEscalationRule(),
    ]
