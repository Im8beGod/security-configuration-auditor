from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack
from app.knowledge_packs.arista_eos_4.mappings import MAPPINGS, PHASE7_MAPPINGS


ARISTA_EOS_4_KNOWLEDGE_PACK_V1 = KnowledgePack(
    knowledge_pack_id=UUID("a4000000-0000-5000-8000-000000000004"),
    knowledge_pack_version_id=UUID("a4010000-0000-5000-8000-000000000004"),
    name="arista_eos_4", version="1.0.0", schema_version="1.0.0",
    profile_id="arista.eos.4", profile_version_id="arista.eos.4@1.0.0",
    mappings=MAPPINGS,
)


ARISTA_EOS_4_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("a4000000-0000-5000-8000-000000000004"),
    knowledge_pack_version_id=UUID("a4010000-0000-5000-8000-000000000104"),
    name="arista_eos_4", version="1.1.0", schema_version="1.0.0",
    profile_id="arista.eos.4", profile_version_id="arista.eos.4@1.0.0",
    mappings=PHASE7_MAPPINGS,
)
