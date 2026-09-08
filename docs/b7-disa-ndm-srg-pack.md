# B7 DISA Network Device Management SRG scoped technical pack

`disa_ndm_srg_v5r5_scoped_technical` version `1` is a scoped technical
prototype subset of the DISA Network Device Management SRG V5R5. It is not
full STIG/SRG compliance, DoD certification, or STIG certification.

The official source is `U_NDM_V5R5_SRG.zip` from DISA Cyber Exchange, retrieved
2026-09-09. Its SHA-256 is
`d6f4415ed5cb4d4c5e589b3e8060203f43742b490aa30be479c774c6ef292a92`.
The package benchmark ID is `Network_Device_Management_SRG`; its XCCDF is
`U_NDM_SRG_V5R5_Manual-xccdf.xml`. The repository retains only compact source
metadata and selected identifiers, not the upstream package or check/fix prose.

Six automated technical checks consume existing B5 EffectiveStates for
administrative idle timeout, logging enablement and remote destination, NTP
authentication, NTP configuration, and configured NTP source. Two obligations
remain manual because current configuration evidence cannot prove FIPS-approved
remote-maintenance cryptography or that audit records use the internal clock.

The same canonical obligations apply across Cisco IOS XE 17, FortiOS 7, and
Junos 18. Missing, conflicting, unsupported, or unsafe multi-scope evidence is
UNKNOWN, never PASS. Time synchronization health, authoritative-source status,
central log delivery, boundary-device redundancy, FIPS validation, policies,
and procedures remain out of scope.
