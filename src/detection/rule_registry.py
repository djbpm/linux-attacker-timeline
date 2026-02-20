from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.ssh_bruteforce_success import SSHBruteForceSuccessRule


def get_rules():
    return [
        SSHBruteForceRule(),
        SSHBruteForceSuccessRule(),
    ]


def get_all_rules():
    return get_rules()