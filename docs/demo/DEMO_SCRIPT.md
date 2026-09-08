# SIH 26155 Demo Script

Target runtime: approximately 120 seconds. Use one Cisco IOS XE 17.x device
and one FortiOS 7.x device with prepared evidence.

## 0-15 Seconds: Fleet View

Show the dashboard and device list. Say: "This is an evidence-first,
multi-vendor auditor for Cisco IOS XE 17.x and FortiOS 7.x. Both vendors use
their own structural reader, then converge into one canonical compliance path."

## 15-35 Seconds: One Batch, Multiple Devices

Submit the Cisco and FortiOS snapshots together through the batch workflow.
Point out the two per-device results, independent audit IDs, and independent
jobs. Say: "This is a real multi-device submission, not multiple files being
treated as one device. A rejected item would be reported without discarding a
valid item."

## 35-60 Seconds: Findings and Remediation

Open the resulting findings. Show PASS, FAIL, and UNKNOWN where present,
severity, observed evidence, and a selected NIST reference. Open a Cisco FAIL
and preview the reviewed SSH v2, remote logging, or NTP procedure. Say:
"The compliance result is deterministic. The remediation is a reviewed preview;
the system does not execute commands."

## 60-85 Seconds: Review Center

Open an unresolved syntax item. Show its evidence and candidate fields, then
request the optional AI suggestion if the environment exposes the disabled
provider state. Say: "AI assistance is advisory. The administrator edits or
reviews the mapping, runs deterministic validation, and approves publication."

## 85-105 Seconds: Impact and Re-Evaluation

Show mapping impact analysis, publish a validated Knowledge Pack version, and
start an explicit re-evaluation. Say: "The same historical Snapshot evidence
is reused. A new immutable Audit revision is created, while the old result
remains available for comparison."

## 105-120 Seconds: Report and Close

Generate the PDF report. Show Device Identification, hostname, vendor,
software version, model or serial when persisted, findings, evidence, severity,
NIST mappings, and remediation data. Close with: "The value is traceable,
deterministic compliance evidence across two vendors, with supervised learning
and immutable history. The result is mapped to selected NIST SP 800-53 Rev. 5
controls; it is not a claim of certification or full framework compliance."
