from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack
from app.knowledge_packs.cisco_iosxe_17.mappings import MAPPINGS


CISCO_IOS_XE_17_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("33ededa8-0c17-55e0-b104-302fc55de5b8"),
    knowledge_pack_version_id=UUID("17e3e913-17df-53bf-b8c1-5cae4bfa133e"),
    name="cisco_iosxe_17",
    version="1.0.0",
    schema_version="1.0.0",
    profile_id="cisco.ios_xe.17",
    profile_version_id="cisco.ios_xe.17@1.0.0",
    mappings=MAPPINGS,
)
