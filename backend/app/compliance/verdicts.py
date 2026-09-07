from enum import Enum


class FindingVerdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    MANUAL_REVIEW = "manual_review"
    NOT_APPLICABLE = "not_applicable"
    PROCESS_ERROR = "process_error"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
