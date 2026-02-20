from src.detection.rules.log_tampering import LogTamperingRule
from src.detection.rules.ssh_bruteforce import SSHBruteForceRule
from src.detection.rules.ssh_bruteforce_success import SSHBruteForceSuccessRule
from src.detection.rules.sudo_privilege_escalation import SudoPrivilegeEscalationRule
from src.detection.rules.reverse_shell import ReverseShellRule
from src.detection.rules.new_user_creation import NewUserCreationRule
from src.detection.rules.multi_stage_attack import MultiStageAttackRule
from src.detection.rules.cron_persistence import CronPersistenceRule
from src.detection.rules.sensitive_file_access import SensitiveFileAccessRule
from src.detection.rules.network_beaconing import NetworkBeaconingRule



def get_rules():
    return [
        SSHBruteForceRule(),
        SSHBruteForceSuccessRule(),
        SudoPrivilegeEscalationRule(),
        ReverseShellRule(),
        NewUserCreationRule(),
        MultiStageAttackRule(),
        CronPersistenceRule(),
        SensitiveFileAccessRule(),
        LogTamperingRule(),
        NetworkBeaconingRule(),



    ]
def get_all_rules():
    return get_rules()
