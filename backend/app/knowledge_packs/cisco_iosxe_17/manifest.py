from uuid import UUID

from app.interpretation.knowledge_pack import KnowledgePack
from app.knowledge_packs.cisco_iosxe_17.mappings import B4_MAPPINGS, MAPPINGS

CISCO_IOS_XE_17_KNOWLEDGE_PACK_V1_1 = KnowledgePack(
    knowledge_pack_id=UUID("33ededa8-0c17-55e0-b104-302fc55de5b8"),
    knowledge_pack_version_id=UUID("dbad6d61-97d6-5e42-a1aa-feb4e28e15b0"),
    name="cisco_iosxe_17", version="1.1.0", schema_version="1.0.0",
    profile_id="cisco.ios_xe.17", profile_version_id="cisco.ios_xe.17@1.0.0",
    mappings=B4_MAPPINGS,
)


CISCO_IOS_XE_17_KNOWLEDGE_PACK = KnowledgePack(
    knowledge_pack_id=UUID("33ededa8-0c17-55e0-b104-302fc55de5b8"),
    knowledge_pack_version_id=UUID("cac42149-9da9-5d13-94d7-12d2c9ae5b05"),
    name="cisco_iosxe_17",
    version="1.2.0",
    schema_version="1.0.0",
    profile_id="cisco.ios_xe.17",
    profile_version_id="cisco.ios_xe.17@1.0.0",
    mappings=MAPPINGS,
)
