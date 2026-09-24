"""Detection Rules Package."""

from backend.app.detection.rules.rule_001_brute_force import RuleBruteForceLogin
from backend.app.detection.rules.rule_002_login_after_failures import RuleLoginAfterFailures
from backend.app.detection.rules.rule_003_privilege_change import RuleSuspiciousPrivilegeChange
from backend.app.detection.rules.rule_004_auth_pattern import RuleSuspiciousAuthPattern
from backend.app.detection.rules.rule_005_indicator_match import RuleExplicitIndicatorMatch

DEFAULT_RULES = [
    RuleBruteForceLogin(),
    RuleLoginAfterFailures(),
    RuleSuspiciousPrivilegeChange(),
    RuleSuspiciousAuthPattern(),
    RuleExplicitIndicatorMatch(),
]

__all__ = [
    "RuleBruteForceLogin",
    "RuleLoginAfterFailures",
    "RuleSuspiciousPrivilegeChange",
    "RuleSuspiciousAuthPattern",
    "RuleExplicitIndicatorMatch",
    "DEFAULT_RULES",
]
