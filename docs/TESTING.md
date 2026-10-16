# Test scope and status

## Untested source change

Ethernet gateway support is implemented, including Ethernet-only firmware, interface priority and IPv4/IPv6 LAN hooks. At the user's request, no configuration validation, code generation, builds, unit tests or device tests were run after this change. Devices remain on the preceding source. All evidence below belongs to its stated source hash, not to the current untested source. The Ethernet example has not been validated. CI is skipped for this publication.

## Focused upstream suite

The prepared upstream snapshot has **219 Mesh C++ cases** with ASan/UBSan and **23 focused Python cases**, plus six subtests. Existing provider/IP-address baseline cases remain in their own suites. Four native fixtures cover Xtensa automatic IPv4, RISC-V automatic IPv6, no-WiFi IPv6 and manual membership IPv4; C5/C6 have config-only fixtures. Native profiles were not recompiled merely for the fixture reduction.

See [upstream reproduction](../upstream/README.md). The external repository's CI is prepared to validate and generate the three user examples against pinned Stock ESPHome with local components. It has not run on the current source. It does not flash devices, run remote hardware or claim radio performance. The full development Lab suite is not included here.

## Physical evidence and limits

Three ESP32-S3 devices still run the preceding compatibility source, identified by `9938a5f3`. Their normal native connectivity, encrypted API identity and complete web responses were verified after deployment. The Ethernet implementation has not been deployed.

The preceding `30eecc94` compatibility source has separate evidence for:

- IPv4 and IPv6 mesh OTA with 122/122 complete parallel web responses.
- Gateway cut/return behavior: each cut produced one observed interruption, and 97/97 return requests completed without a second episode. This is scoped evidence across attempts, not one flawless pipeline run; IPv6 failover was not separately measured.
- Fresh-RAM boot without WiFi, dual-stack services and default-alias OTA with the isolated upstream-candidate CLI.
- A separate 600-second normal-operation run with 366 complete IPv4/IPv6 responses and no observed native disconnect.

On deployed source `9938a5f3`, an AP-hint attempt connected with DHCP after 15.023 seconds, followed by a 90-second native hold. The old recovery deadline was 15 seconds; the corrected 60-second bound allows longer normal authentication attempts without additional RAM. This is not a controlled performance comparison.

**The complete manual WiFi-OFF/180-second mesh/WiFi-ON case remains unqualified.** Its last run aborted because an observer treated IPv6-only readiness while IPv4 DHCP was pending as a usable IPv4 address change. The provider excludes an unspecified IPv4 address, and the original IPv4 returned after DHCP. The original run stays failed; safe normal restoration passed. A one-line test-guard correction was prepared but no additional physical run was performed.

Early authentication expiry also occurred on Stock ESPHome on C, without its local mesh component. A/B mesh radios remained active, so this does not isolate all radio effects or establish the cause. No router, PMF, power or hardware cause is proven.

## Useful community checks

Start with two or three nodes and a non-critical setup. Record the pinned repo tag/commit, ESPHome and IDF versions, chip, power-save option, topology and which address family is used. Report full API/web/OTA results and the actual native/mesh transition, not just a ping. Gateway loss/return and the outstanding manual return case are particularly useful. Do not upload WiFi passwords, mesh/API keys, complete secrets files or unredacted personal logs.

No throughput, large-network, Ethernet, alternate-radio, HIGH-power-save or ESP8266 qualification is claimed by this alpha.
