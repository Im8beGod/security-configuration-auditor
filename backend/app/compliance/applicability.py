from app.compliance.models import ApplicabilityResult, ApplicabilityStatus, RulePack
from app.db.models import Audit
from app.effective_state.contracts import UnresolvedReason


def determine_applicability(audit: Audit, rule_pack: RulePack) -> ApplicabilityResult:
    """Use persisted profile metadata only; uncertainty is never non-applicability."""
    resolution = audit.profile_resolution
    if resolution.get("resolution_status") != "resolved":
        return ApplicabilityResult(ApplicabilityStatus.UNRESOLVED, UnresolvedReason.UNSUPPORTED_PROFILE)
    if resolution.get("profile_version_id") != rule_pack.profile_version_id:
        return ApplicabilityResult(ApplicabilityStatus.NOT_APPLICABLE)
    # The profile-specific rule pack is authoritative; device classes are vendor-specific.
    return ApplicabilityResult(ApplicabilityStatus.APPLICABLE)
