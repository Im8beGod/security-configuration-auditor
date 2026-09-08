# SIH 26155 Five-Slide Presentation Content

## Slide 1: Problem and Solution

- Network configuration evidence is fragmented across vendors and devices.
- Raw syntax is not the same as effective security state.
- SIH 26155 preserves evidence and produces deterministic, reviewable findings.
- Cisco IOS XE 17.x and FortiOS 7.x converge into shared security semantics.

Suggested visual: two configuration panels flowing into one trusted findings
panel.

Speaker note: Emphasize bounded support and traceability rather than broad
vendor or framework claims.

## Slide 2: Architecture and Multi-Vendor Flow

- Upload or batch submission creates immutable Artifact/Snapshot boundaries.
- Cisco uses `indentation_cli.v1`; FortiOS uses `fortios_cli.v1`.
- Both flow through SecurityFacts, EffectiveState, and one compliance engine.
- Findings retain severity, evidence, provenance, and report references.

Suggested visual: left-to-right pipeline with two reader branches merging before
EffectiveState.

Speaker note: The shared engine keeps verdict semantics consistent while the
evidence preserves vendor syntax.

## Slide 3: Key Differentiators

- Deterministic PASS/FAIL/UNKNOWN evaluation.
- Supervised learning loop with validation and administrator approval.
- Immutable Knowledge Packs and historical re-evaluation revisions.
- Cisco and FortiOS support in one vendor-neutral model.
- Mapped to selected NIST SP 800-53 Rev. 5 controls.

Suggested visual: shield-shaped trust model around evidence, mappings, and
historical revisions.

Speaker note: AI suggestions are advisory and never determine compliance.

## Slide 4: Demo, Results, and Security Guarantees

- Submit Cisco and FortiOS devices in one stateless batch with per-device jobs.
- Review findings, severity, evidence, and selected NIST mappings.
- Generate PDF reports with device identity and hardware details.
- Preview reviewed Cisco remediation procedures without command execution.
- Tenant isolation and immutable evidence protect audit history.

Suggested visual: batch result list beside a finding and PDF report excerpt.

Speaker note: FortiOS remediation remains unavailable pending reviewed
procedure publication.

## Slide 5: Impact, Scalability, Roadmap, and Close

- Independent device jobs provide a narrow path to larger fleet workflows.
- Persistent evidence and reports support repeatable review and audit trails.
- Current scope is Cisco IOS XE 17.x, FortiOS 7.x, and selected NIST mappings.
- Future work can add reviewed vendors, frameworks, and remediation catalogs.
- Close: deterministic, traceable compliance evidence without overclaiming.

Suggested visual: current bounded scope on the left and a clearly labeled
future expansion path on the right.

Speaker note: CIS, DISA STIG, and ISO mapping packs are not currently
implemented; no claim of NIST compliance or certification is made.
