from enum import Enum


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class UnresolvedReason(str, Enum):
    UNKNOWN_SYNTAX = "unknown_syntax"
    UNKNOWN_SEMANTICS = "unknown_semantics"
    MISSING_EVIDENCE = "missing_evidence"
    UNSUPPORTED_FEATURE = "unsupported_feature"
    AMBIGUOUS_SCOPE = "ambiguous_scope"
    UNRESOLVED_DEFAULT = "unresolved_default"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNSUPPORTED_PROFILE = "unsupported_profile"
