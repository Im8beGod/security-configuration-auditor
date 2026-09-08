# B6 NIST SP 800-53 Rev. 5 scoped technical pack

`nist_sp80053_rev5_scoped_technical` version `1` is an immutable, published
AssessmentPack. It is deliberately a bounded device-configuration evidence
pack, not an assertion of complete NIST control compliance.

## Official provenance

The selected identifiers and titles were checked against NIST's official OSCAL
catalog `NIST_SP-800-53_rev5_catalog.json`, version 5.2.0, last modified
2026-05-11. The exact retrieved artifact is pinned to OSCAL content commit
`78650f02ad9321bb7b817846f8fbd4f2bcd620de` and SHA-256
`01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062`.
The repository retains only the small identifier/title subset and provenance
in `backend/app/assessment_packs/nist_sp80053_rev5_subset.json`; it does not
copy catalog prose.

## Included technical evidence

The pack contains eight automated, deterministic technical checks and two
manual checks. Automated checks consume only B5 EffectiveStates:

- AC-17: SSH enabled, Telnet disabled, explicit SSH v2, and bounded idle timeout.
- AU-12: explicit logging enabled and a remote logging destination.
- AU-8: NTP configured and an NTP server configured.

AC-17 remote-access authorization/monitoring and AU-12 audit event selection
and review remain MANUAL. They do not produce a fabricated automated verdict.

For an automated item, PASS requires affirmative, resolved evidence; a
deterministic contrary configuration is FAIL; missing, unsupported,
conflicting, or multiple native scopes are UNKNOWN. Native scopes are never
collapsed into a device-wide conclusion.

The same vendor-neutral obligations apply to Cisco IOS XE 17, FortiOS 7, and
Junos 18 canonical state. A vendor's unsupported semantic is UNKNOWN, not
PASS. This pack intentionally does not assess authorization workflows, audit
event completeness, log delivery, time synchronization health, TLS transport,
cryptographic strength, policy, personnel, or review-frequency requirements.
