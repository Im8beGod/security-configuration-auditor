# B5 semantic expansion

B5 expands canonical SecurityFacts and EffectiveStates only.  It does not add
framework AssessmentPacks, framework verdicts, policy engines, or AI authority.

The built-in semantic packs now expose explicit, provenance-preserving evidence
for management transport/source controls, administrative session controls,
management TLS, logging enablement, NTP authentication, and the previously
available remote logging and NTP destination semantics.  Native interface,
administrator, VTY, and XML-qualified scopes remain distinct; unsupported
scope qualification resolves to UNKNOWN rather than device-wide truth.

## Semantic coverage matrix

| Canonical semantic | Cisco IOS XE 17 | FortiOS 7 | Junos 18 XML | Scope and evidence limitation |
| --- | --- | --- | --- | --- |
| `management.remote.ssh.enabled` | SUPPORTED | SUPPORTED | SUPPORTED | Cisco VTY, FortiOS interface, Junos device; absence is no fact. |
| `management.remote.telnet.enabled` | SUPPORTED | SUPPORTED | UNSUPPORTED | Cisco VTY and FortiOS interface only. FortiOS port settings are not evidence. |
| `management.remote.source.restriction.configured` | SUPPORTED | SUPPORTED | UNSUPPORTED | Cisco VTY access-class reference and FortiOS administrator trusthost. |
| `management.remote.source.permitted_network` | UNSUPPORTED | SUPPORTED | UNSUPPORTED | FortiOS administrator trusthost address/mask only. |
| `management.session.idle_timeout` | SUPPORTED | SUPPORTED | PARTIAL | Seconds; Cisco VTY, FortiOS device, Junos explicit XML login timeout. |
| `management.remote.ssh.version` | SUPPORTED | UNSUPPORTED | UNSUPPORTED | Explicit Cisco SSH version only. |
| `management.remote.https.enabled` | UNSUPPORTED | SUPPORTED | UNSUPPORTED | Explicit FortiOS interface `allowaccess` only. |
| `management.remote.tls.minimum_version` | UNSUPPORTED | SUPPORTED | UNSUPPORTED | Explicit FortiOS configured TLS-version set; no inferred security boolean. |
| `logging.enabled` | SUPPORTED | SUPPORTED | UNSUPPORTED | Explicit Cisco `logging on` or FortiOS log status enable only. |
| `logging.remote.destination` | SUPPORTED | SUPPORTED | SUPPORTED | Repeatable; destination does not prove logging is enabled. |
| encrypted logging transport | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | No reviewed fixture evidence explicitly proves encryption. |
| `time.ntp.server` | SUPPORTED | SUPPORTED | SUPPORTED | Repeatable; routing-instance-qualified Junos values are not flattened. |
| `time.ntp.configured` | SUPPORTED | SUPPORTED | SUPPORTED | Explicit server configuration only; it does not prove synchronization health. |
| `time.ntp.authentication.enabled` | SUPPORTED | UNSUPPORTED | UNSUPPORTED | Explicit Cisco NTP authentication only. |
| `time.ntp.authentication.key_id` | SUPPORTED | UNSUPPORTED | UNSUPPORTED | Repeatable Cisco key ID; secret material is not extracted. |
| `time.ntp.authentication.trusted_key_id` | SUPPORTED | UNSUPPORTED | UNSUPPORTED | Repeatable Cisco trusted-key ID. |

## Pre-existing migration/model differences

The missing profile-manifest organization index and the Snapshot foreign-key
`RESTRICT`/model `CASCADE` difference pre-date B5.  B5 makes no schema or
migration change for either item because neither intersects the semantic
expansion.
