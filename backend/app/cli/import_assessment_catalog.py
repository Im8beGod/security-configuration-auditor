import argparse
from pathlib import Path
from uuid import UUID

from app.assessment_packs.catalog import CatalogImportError, import_external_catalog
from app.core.config import get_settings
from app.db.engine import create_database_engine
from app.db.session import create_session_factory


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a manual-only CIS or ISO assessment catalog")
    parser.add_argument("--organization-id", required=True, type=UUID)
    parser.add_argument("--file", required=True, type=Path)
    args = parser.parse_args()
    try:
        content = args.file.read_bytes()
        engine = create_database_engine(get_settings())
        factory = create_session_factory(engine)
        with factory.begin() as db:
            pack, counts = import_external_catalog(
                db, args.organization_id, content, args.file.name,
            )
            print(
                f"imported={pack.assessment_pack_version_id} version={pack.version} "
                f"manual={counts['manual']} unimplemented={counts['unimplemented']} automatic=0"
            )
        engine.dispose()
        return 0
    except (CatalogImportError, OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
