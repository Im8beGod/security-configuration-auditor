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
- Juniper Junos 18.x XML onboarding uses the generic XML structural reader and
  declarative ProfileManifest mappings.
- All prototype-supported profiles converge into shared canonical semantics,
  EffectiveState, and the deterministic compliance engine.
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

Implemented AssessmentPacks provide scoped technical prototype coverage for
NIST SP 800-53 Rev. 5, DISA Network Device Management SRG, and the CIS Cisco
IOS XE 17.x Benchmark v2.2.1. ISO/IEC 27001:2022 is technical alignment derived
through NIST OLIR. These are not claims of certification, full framework
coverage, universal compliance, CIS-CAT equivalence, or ISO conformity
assessment.

Remediation is reviewed, profile-scoped guidance across Cisco, FortiOS, and
Junos. It is preview-only: commands are never executed automatically. Vendor
and version coverage remains intentionally bounded.
