# External CIS and ISO catalog import

Administrators can import licensed or organization-supplied CIS and ISO JSON
catalogs without adding application code. Imports are tenant-scoped, immutable,
versioned, and deliberately manual-only. They never create evaluator bindings or
automatic PASS results.

Required JSON shape:

```json
{
  "schema_version": "1.0.0",
  "framework": "cis",
  "catalog_id": "licensed-iosxe-benchmark",
  "name": "Licensed IOS XE benchmark",
  "source_version": "v2.2.1",
  "source_url": "https://publisher.example/catalog",
  "profile_version_ids": ["cisco.ios_xe.17@1.0.0"],
  "controls": [
    {
      "control_id": "1.1",
      "title": "Publisher control title",
      "severity": "high",
      "scope": "device",
      "implementation_status": "manual"
    }
  ]
}
```

`framework` is `cis` or `iso`. Each control must be `manual` or
`unimplemented`; `evaluator_rule_id` is rejected. The service computes the
SHA-256 digest of the exact uploaded bytes and stores it with the source URL and
version on both the pack and every obligation.

API: authenticated administrators upload the JSON file as multipart field
`file` to `POST /api/v1/assessment-packs/import`.

CLI:

```powershell
python -m app.cli.import_assessment_catalog `
  --organization-id 00000000-0000-0000-0000-000000000000 `
  --file .\licensed-catalog.json
```

Importing the same `catalog_id` again creates the next immutable tenant version.
The importer does not claim completeness, certification, or automated coverage.
