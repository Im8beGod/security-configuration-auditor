# SIH 26155 judge demo runbook

Target duration: 3-5 minutes. Use only local development data and never show
credentials, secrets, or a real customer configuration.

1. **Login and dashboard (0:00-0:30).** Sign in and open the Fleet Dashboard.
   Introduce SIH 26155 as an evidence-first, multi-vendor security compliance
   auditor with immutable, revision-aware records.
2. **Evidence and Snapshot (0:30-1:15).** Upload the repository-safe Cisco IOS
   XE development fixture
   `backend/tests/fixtures/cisco_ios_xe/representative.cfg`. Create or confirm
   the Device and immutable Snapshot. Explain that vendor syntax is normalized
   into shared security semantics.
3. **Audit (1:15-2:00).** Select an applicable AssessmentPack and run the audit.
   Show the deterministic PASS/FAIL/UNKNOWN summary and explain that framework
   packs are scoped technical coverage, not certification.
4. **Evidence and guidance (2:00-3:00).** Open a FAIL or UNKNOWN finding. Show
   its persisted evidence and provenance, then show the reviewed remediation
   preview. Emphasize that it is guidance only: no device command is executed.
5. **Extensibility and close (3:00-4:00).** Briefly show the low-code mapping
   and Knowledge Pack workflow: executable validation, human approval, then
   immutable publication for future audits. If available, note that local
   Ollama offers suggestions only; it has no verdict or approval authority.
6. **Report and fleet view (4:00-5:00).** Generate/download the PDF report and
   return to the Fleet Dashboard. Close with: “The result is deterministic,
   evidence-backed, reviewable, and safely bounded as a prototype.”
