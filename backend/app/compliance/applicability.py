from app.compliance.models import ApplicabilityResult, ApplicabilityStatus, RulePack
from app.db.models import Audit, DeviceClass
from app.effective_state.contracts import UnresolvedReason
from app.profile_resolution import CISCO_IOS_XE_17


def determine_applicability(audit: Audit, rule_pack: RulePack) -> ApplicabilityResult:
    """Use persisted profile metadata only; uncertainty is never non-applicability."""
    resolution = audit.profile_resolution
    if resolution.get("resolution_status") != "resolved":
        return ApplicabilityResult(ApplicabilityStatus.UNRESOLVED, UnresolvedReason.UNSUPPORTED_PROFILE)
    if resolution.get("profile_version_id") != rule_pack.profile_version_id:
        return ApplicabilityResult(ApplicabilityStatus.NOT_APPLICABLE)
    device_class = resolution.get("device_class")
    if device_class is None:
        # Profile evidence currently does not persist a device class; the selected profile is authoritative.
        return ApplicabilityResult(ApplicabilityStatus.APPLICABLE)
    if device_class not in {item.value for item in CISCO_IOS_XE_17.device_classes}:
        return ApplicabilityResult(ApplicabilityStatus.NOT_APPLICABLE)
    return ApplicabilityResult(ApplicabilityStatus.APPLICABLE)
