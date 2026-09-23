import json
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest

from app.db.models import MappingOrigin, MappingStatus, UnresolvedReviewStatus, UserRole
from app.profile_resolution.runtime import parse_runtime_profile
from app.training.ai import AISuggestionInvalid, MappingSuggestion, OllamaSuggestionProvider, build_prompt
from app.training.dsl import MappingDefinition
from app.training.service import TrainingError, adopt_suggestion, suggest_mapping


class Db:
    def __init__(self, block):
        self.block = block
        self.added = []
        self.committed = False

    def scalar(self, _statement):
        return self.block

    def add(self, value):
        self.added.append(value)

    def flush(self):
        pass

    def commit(self):
        self.committed = True


class Provider:
    def __init__(self, suggestion):
        self.suggestion = suggestion
        self.context = None
        self.profile = None

    def suggest_mapping(self, context, profile=None):
        self.context, self.profile = context, profile
        return self.suggestion


def _profile(reader):
    profile_id = f"runtime.stage8.{reader.split('_', 1)[0]}"
    evidence = ["configuration"] if reader == "indentation_cli.v1" else ["structured_export"]
    raw = {
        "schema_version": "1.0.0", "profile_id": profile_id,
        "profile_version": "1.0.0", "profile_version_id": f"{profile_id}@1.0.0",
        "vendor": "Stage Eight", "product_family": "Runtime", "os": "TestOS",
        "structural_reader": reader, "evidence_types": evidence,
        "device_classes": ["router"], "detection": {"tokens": ["StageEight"]},
        "version_constraints": {"supported_major_versions": [1]},
        "capabilities": ["structural_parsing", "semantic_interpretation", "effective_state_resolution", "administrator_training"],
    }
    return parse_runtime_profile(json.dumps(raw).encode())


def _definition(profile, reader):
    cli_examples = [
        {"family": family, "node": {"command": "stage8-ssh", "arguments": ["enable"], "negated": False}, "expected_match": True, "expected_value": True}
        for family in ("positive", "alternate_values", "wrong_scope", "negation", "conflict")
    ] + [
        {"family": "negative", "node": {"command": "stage8-ssh", "arguments": ["disable"], "negated": False}, "expected_match": False},
        {"family": "regression", "node": {"command": "other", "arguments": ["enable"], "negated": False}, "expected_match": False},
    ]
    base = {
        "profile_applicability": {"profile_version_ids": [profile.profile_version_id]},
        "target_field_id": "management.remote.ssh.enabled",
        "unit_conversion": {"operation": "none"}, "scope_resolution": {"strategy": "device"},
        "negation_behavior": {"operation": "unsupported"}, "removal_behavior": {"operation": "unsupported"},
        "default_behavior": {"operation": "unknown"}, "examples": cli_examples if reader == "indentation_cli.v1" else [],
    }
    if reader == "xml_tree.v1":
        return MappingDefinition.model_validate({**base,
            "structural_match": {"operation": "xml_path", "command": "xml", "xml_path": {"path": [{"local_name": "configuration"}, {"local_name": "ssh"}], "source": "presence"}},
            "value_extraction": {"operation": "boolean_from_presence", "output_type": "boolean"},
        })
    if reader == "json_tree.v1":
        return MappingDefinition.model_validate({**base,
            "structural_match": {"operation": "json_path", "command": "json", "json_path": {"path": [{"key": "management"}, {"key": "ssh"}, {"key": "enabled"}], "source": "value", "capture": "enabled", "value_type": "boolean"}},
            "value_extraction": {"operation": "capture", "capture": "enabled", "output_type": "boolean"},
        })
    return MappingDefinition.model_validate({**base,
        "structural_match": {"command": "stage8-ssh", "arguments": [{"operation": "literal", "value": "enable"}]},
        "value_extraction": {"operation": "constant", "value": True, "output_type": "boolean"},
    })


def _block(profile):
    return SimpleNamespace(
        unresolved_block_id=uuid4(), fingerprint=uuid4().hex, profile_version_id=profile.profile_version_id,
        raw_text="stage8-ssh enable", surrounding_context="runtime test", candidate_field_ids=["management.remote.ssh.enabled"],
        occurrence={"command": "stage8-ssh", "scope_type": "device"}, evidence_refs=[],
        assigned_mapping_version_id=None, review_status=UnresolvedReviewStatus.OPEN,
    )


def _user():
    return SimpleNamespace(user_id=uuid4(), organization_id=uuid4(), role=UserRole.ADMIN)


@pytest.mark.parametrize("reader", ["indentation_cli.v1", "xml_tree.v1", "json_tree.v1"])
def test_runtime_profiles_receive_the_resolved_manifest_in_ai_suggestions(monkeypatch, reader):
    profile, user = _profile(reader), _user()
    block, db = _block(profile), Db(None)
    suggestion = MappingSuggestion(definition=_definition(profile, reader), description="bounded runtime suggestion", confidence=0.5)
    provider = Provider(suggestion)
    monkeypatch.setattr("app.training.service.get_unresolved", lambda *_args: block)
    monkeypatch.setattr("app.training.service.profile_for", lambda _db, organization_id, profile_id: profile if organization_id == user.organization_id and profile_id == profile.profile_version_id else None)

    preview = suggest_mapping(db, user, block.unresolved_block_id, provider, "stage8-signing-key")

    assert provider.profile is profile
    assert provider.context.profile_version_id == profile.profile_version_id
    assert preview.suggestion.definition.profile_applicability.profile_version_ids == [profile.profile_version_id]
    prompt = build_prompt(provider.context, "mocked", provider.profile)
    assert json.loads(prompt["messages"][1]["content"])["profile"]["reader"] == reader


def test_runtime_ai_adoption_creates_only_an_editable_draft(monkeypatch):
    profile, user = _profile("indentation_cli.v1"), _user()
    block = _block(profile)
    db = Db(block)
    suggestion = MappingSuggestion(definition=_definition(profile, "indentation_cli.v1"), description="draft only", confidence=0.5)
    provider = Provider(suggestion)
    monkeypatch.setattr("app.training.service.get_unresolved", lambda *_args: block)
    monkeypatch.setattr("app.training.service.profile_for", lambda *_args: profile)
    preview = suggest_mapping(db, user, block.unresolved_block_id, provider, "stage8-signing-key")

    mapping = adopt_suggestion(db, user, block.unresolved_block_id, preview.adoption_token, "stage8-signing-key")

    assert mapping.status is MappingStatus.DRAFT and mapping.origin is MappingOrigin.AI_ASSISTED
    assert block.assigned_mapping_version_id == mapping.mapping_version_id
    assert db.committed


def test_invalid_ai_output_and_profile_mismatch_are_rejected(monkeypatch):
    profile, user = _profile("indentation_cli.v1"), _user()
    block, db = _block(profile), Db(None)
    monkeypatch.setattr("app.training.service.get_unresolved", lambda *_args: block)
    monkeypatch.setattr("app.training.service.profile_for", lambda *_args: profile)

    invalid = Provider(SimpleNamespace(model_dump=lambda **_kwargs: {"definition": {"target_field_id": "invented.field"}, "description": "bad", "confidence": 0.5}))
    with pytest.raises(AISuggestionInvalid):
        suggest_mapping(db, user, block.unresolved_block_id, invalid, "stage8-signing-key")

    other = _profile("json_tree.v1")
    mismatch = Provider(MappingSuggestion(definition=_definition(other, "json_tree.v1"), description="wrong profile", confidence=0.5))
    with pytest.raises(AISuggestionInvalid):
        suggest_mapping(db, user, block.unresolved_block_id, mismatch, "stage8-signing-key")
    assert not db.added and not db.committed


def test_another_tenants_runtime_profile_is_inaccessible(monkeypatch):
    profile, owner, other = _profile("indentation_cli.v1"), _user(), _user()
    block, db = _block(profile), Db(None)
    provider = Provider(MappingSuggestion(definition=_definition(profile, "indentation_cli.v1"), description="isolated", confidence=0.5))
    monkeypatch.setattr("app.training.service.get_unresolved", lambda *_args: block)
    monkeypatch.setattr("app.training.service.profile_for", lambda _db, organization_id, _profile_id: profile if organization_id == owner.organization_id else None)

    with pytest.raises(TrainingError, match="Resolved profile"):
        suggest_mapping(db, other, block.unresolved_block_id, provider, "stage8-signing-key")


def test_two_invalid_ollama_proposals_create_no_runtime_draft(monkeypatch, auth_settings):
    profile, user = _profile("indentation_cli.v1"), _user()
    block, db = _block(profile), Db(None)
    other = _profile("json_tree.v1")
    invalid = MappingSuggestion(definition=_definition(other, "json_tree.v1"), description="wrong profile", confidence=0.5)
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={"done": True, "message": {"content": json.dumps(invalid.model_dump(mode="json", exclude={"provider_metadata", "similar_mapping_refs"}))}})

    monkeypatch.setattr("app.training.service.get_unresolved", lambda *_args: block)
    monkeypatch.setattr("app.training.service.profile_for", lambda *_args: profile)
    provider = OllamaSuggestionProvider(auth_settings, httpx.MockTransport(respond))

    with pytest.raises(AISuggestionInvalid):
        suggest_mapping(db, user, block.unresolved_block_id, provider, "stage8-signing-key")

    assert len(calls) == 2
    assert not db.added and not db.committed
