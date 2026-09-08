from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack
from app.knowledge_packs.juniper_junos_18.mappings import MAPPINGS

JUNIPER_JUNOS_18_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("b3000000-0000-5000-8000-000000000018"),
    knowledge_pack_version_id=UUID("b3040000-0000-5000-8000-000000000018"),
    name="juniper_junos_18", version="1.0.0", schema_version="1.0.0",
    profile_id="juniper.junos.18", profile_version_id="juniper.junos.18@1.0.0", mappings=MAPPINGS,
)
