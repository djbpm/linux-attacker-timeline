from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.ssh_bruteforce_success import SSHBruteForceSuccessRule
from src.detection.rules.sudo_privilege_escalation import SudoPrivilegeEscalationRule
from src.detection.rules.reverse_shell import ReverseShellRule
from src.detection.rules.new_user_creation import NewUserCreationRule
from src.detection.rules.multi_stage_attack import MultiStageAttackRule


def get_rules():
    return [
        SSHBruteForceRule(),
        SSHBruteForceSuccessRule(),
        SudoPrivilegeEscalationRule(),
        ReverseShellRule(),
        NewUserCreationRule(),
        MultiStageAttackRule(),
    ]
def get_all_rules():
    return get_rules()
