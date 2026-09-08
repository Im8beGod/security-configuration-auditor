from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack
from app.knowledge_packs.fortios_7.mappings import B4_MAPPINGS, MAPPINGS

FORTIOS_7_KNOWLEDGE_PACK_V1_1 = KnowledgePack(
    knowledge_pack_id=UUID("a1b2c3d4-1111-5aaa-8aaa-000000000013"),
    knowledge_pack_version_id=UUID("a1b2c3d4-3333-5aaa-8aaa-000000000013"),
    name="fortios_7", version="1.1.0", schema_version="1.0.0",
    profile_id="fortinet.fortios.7", profile_version_id="fortinet.fortios.7@1.0.0",
    mappings=B4_MAPPINGS,
)


FORTIOS_7_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("a1b2c3d4-1111-5aaa-8aaa-000000000013"),
    knowledge_pack_version_id=UUID("a1b2c3d4-7333-5aaa-8aaa-000000000013"),
    name="fortios_7",
    version="1.2.0",
    schema_version="1.0.0",
    profile_id="fortinet.fortios.7",
    profile_version_id="fortinet.fortios.7@1.0.0",
    mappings=MAPPINGS,
)
