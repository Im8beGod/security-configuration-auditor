from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping
from uuid import UUID

from app.compliance.models import OrganizationPolicyVersion, deterministic_policy_version_id


class PolicyRegistryError(ValueError):
    pass


class OrganizationPolicyRegistry:
    """Immutable policy-version lookup; policy administration is intentionally out of scope."""

    def __init__(self) -> None:
        self._versions: dict[UUID, OrganizationPolicyVersion] = {}
        self._logical_versions: dict[tuple[UUID, str, str], OrganizationPolicyVersion] = {}

    def register(
        self, *, organization_id: UUID, name: str, version: str, parameters: Mapping[str, Any]
    ) -> OrganizationPolicyVersion:
        if not name.strip() or not version.strip():
            raise PolicyRegistryError("Organization policy metadata is malformed")
        frozen_parameters = MappingProxyType(dict(parameters))
        policy = OrganizationPolicyVersion(
            organization_id=organization_id,
            organization_policy_version_id=deterministic_policy_version_id(
                organization_id, name, version, frozen_parameters
            ),
            name=name,
            version=version,
            parameters=frozen_parameters,
        )
        existing = self._versions.get(policy.organization_policy_version_id)
        if existing is not None and existing != policy:
            raise PolicyRegistryError("Organization policy version identity conflicts")
        logical_key = (organization_id, name, version)
        declared = self._logical_versions.get(logical_key)
        if declared is not None and dict(declared.parameters) != dict(policy.parameters):
            raise PolicyRegistryError("Organization policy version content conflicts")
        self._versions[policy.organization_policy_version_id] = policy
        self._logical_versions[logical_key] = policy
        return policy

    def get(self, version_id: UUID) -> OrganizationPolicyVersion:
        try:
            return self._versions[version_id]
        except KeyError as exc:
            raise PolicyRegistryError("Organization policy version is unavailable") from exc


def resolve_parameter(policy: OrganizationPolicyVersion | None, name: str) -> Any | None:
    return None if policy is None else policy.parameters.get(name)


DEFAULT_POLICY_NAME = "internal_technical_timeout_default"
DEFAULT_POLICY_VERSION = "1.0.0"
DEFAULT_POLICY_PARAMETERS = MappingProxyType({"maximum_admin_idle_timeout_seconds": 600})
POLICY_REGISTRY = OrganizationPolicyRegistry()


def select_policy_version(organization_id: UUID, pinned_version_id: str | None) -> OrganizationPolicyVersion:
    """Select the sole safe prototype policy without inventing destination allow-lists."""
    policy = POLICY_REGISTRY.register(
        organization_id=organization_id, name=DEFAULT_POLICY_NAME,
        version=DEFAULT_POLICY_VERSION, parameters=DEFAULT_POLICY_PARAMETERS,
    )
    if pinned_version_id is None:
        return policy
    try:
        requested = UUID(pinned_version_id)
    except (TypeError, ValueError):
        raise PolicyRegistryError("Organization policy version pin is malformed") from None
    if requested != policy.organization_policy_version_id:
        raise PolicyRegistryError("Organization policy version is unavailable")
    return policy
