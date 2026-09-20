from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack


GENERIC_CLI_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("a5000000-0000-5000-8000-000000000005"),
    knowledge_pack_version_id=UUID("a5010000-0000-5000-8000-000000000005"),
    name="generic_cli",
    version="1.0.0",
    schema_version="1.0.0",
    profile_id="generic.cli",
    profile_version_id="generic.cli@1.0.0",
    mappings=(),
)
