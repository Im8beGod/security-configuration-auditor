# Current Architecture Brief

## System Flow

```text
Upload / batch
-> immutable Artifact and Snapshot
-> profile detection
-> vendor reader
-> canonical SecurityFacts
-> EffectiveState
-> deterministic compliance
-> Findings/Evidence
-> remediation/reporting
```

Each Audit is bound to one immutable Snapshot. Batch submission coordinates
independent device audits and jobs; it does not merge evidence or create a
second audit pipeline.

## Multi-Vendor Boundary

- Cisco IOS XE 17.x uses `indentation_cli.v1`.
- FortiOS 7.x uses `fortios_cli.v1`.
- Both readers produce structural data that converges into shared canonical
  semantics and the same EffectiveState and compliance engine.
- Vendor-specific syntax remains in evidence and provenance; verdict semantics
  remain vendor-neutral.

## Trust Model

- Artifacts and finalized Snapshots are immutable evidence boundaries.
- Organization and tenant checks apply to devices, snapshots, audits, jobs,
  findings, mappings, and reports.
- PASS, FAIL, and UNKNOWN are deterministic results from persisted state.
- AI suggestions are advisory only and have no verdict, approval, or
  publication authority.
- Administrators approve mappings and publication explicitly.
- Published Knowledge Pack versions are immutable.
- Historical Audits are never rewritten; re-evaluation creates a new revision.

## Learning Loop

```text
Unknown syntax
-> UnresolvedBlock
-> optional AI suggestion
-> low-code mapping
-> deterministic seven-family validation
-> human approval
-> immutable publication
```

The manual path works without an AI provider. Suggestions do not become
production mappings without validation and administrator approval.

## Re-Evaluation

```text
New Knowledge Pack
-> explicit administrator initiation
-> SAME historical Snapshot evidence
-> NEW immutable Audit revision
-> old result preserved
```

The current Audit and Knowledge Pack selections remain pinned. Source evidence
is not recollected or replaced during re-evaluation.

## Frameworks and Bounded Claims

The product exposes mappings to selected NIST SP 800-53 Rev. 5 controls for
traceability. It does not claim NIST compliance, certification, or full
framework coverage. CIS, DISA STIG, and ISO mapping packs are not currently
implemented.

Remediation commands are never executed automatically. Reviewed Cisco
remediation procedures currently cover SSH v2, remote logging, and NTP. FortiOS
remediation is unavailable pending reviewed procedure publication. Support is
limited to the documented Cisco IOS XE 17.x and FortiOS 7.x profiles.
