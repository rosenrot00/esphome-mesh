# Upstream PR roadmap

This is a proposed dependency plan, not a list of published or maintainer-approved PRs. Step IDs and anchors are stable so future PRs can link to them. Rows describe review tracks; a large track must be split into several independently buildable PRs before submission.

First discuss the architecture and split with ESPHome maintainers. Their current [submission guide](https://developers.esphome.io/contributing/submitting-your-work/#how-to-approach-large-submissions) caps PRs at 1,000 changed lines outside tests and 15 components/areas. The combined review snapshot in `upstream/patches` is reference material and must not be submitted as one PR.

| ID | Review track | Depends on | Status / upstream PR |
| --- | --- | --- | --- |
| P01 | Generic fallback connection providers and CLI/cache metadata | None | Prepared local foundation; not published |
| P02 | Shared exclusive ESP-NOW SDK owner and teardown fencing | None | Implemented; proposed split |
| P03 | Native WiFi intent and validated AP-hint recovery | P02 | Implemented; proposed split |
| P04 | Portable protocol format and transport contracts | None | Implemented; split codecs/contracts first |
| P05 | Routing, expiry, duplicate suppression and path selection | P04 | Implemented; multiple small PRs expected |
| P06 | Membership, boot/session freshness and shared-key security | P04, P05 | Implemented; split admission/crypto/integration |
| P07 | IP packet framing, fragmentation and bounded delivery | P04, P05 | Implemented; split codec/delivery/queues |
| P08 | IPv4 DHCP, LAN adapter and endpoint ownership | P01, P06, P07 | Implemented; split DHCP/proxy/ownership/integration |
| P09 | IPv6 address/ND handling and LAN discovery | P01, P06, P07 | Implemented; split IPv6 primitives/adapter/discovery |
| P10 | User-facing mesh integration, status and documentation | P01–P09 | Alpha available; upstream integration pending |

<a id="p01-network-providers"></a>
## P01 — Network providers

A generic bounded provider registry reports fallback connection state and usable addresses. Native network interfaces retain precedence. The Python Core and compiled-config cache can retain a provider's default upload/log hostname without a native WiFi block. The provider must not import mesh or expose mesh routing/keys through its interface.

Reference: [foundation patch](../upstream/patches/0001-network-providers.patch). Keep this independently useful and test both native-only configurations and provider-backed CLI/cache behavior.

<a id="p02-espnow-owner"></a>
## P02 — ESP-NOW owner

One common SDK owner coordinates init/deinit and callback lifetime. Stock ESPNow remains functional; simultaneous incompatible consumers are rejected. Sources: `components/espnow_driver/`, and the downstream WiFi/transport integration.

<a id="p03-wifi-recovery"></a>
## P03 — WiFi recovery

Preserve user enable/disable intent, distinguish temporary pauses, validate AP metadata and bound acquisition/recovery. Keep SDK-free AP-hint/deadline tests. Do not grow the generic network-provider API for this radio-specific state.

<a id="p04-protocol"></a>
## P04 — Protocol contracts

Land explicit wire encoding, payload limits, transport capabilities and bounded reader interfaces. Keep ESP-IDF calls outside portable code and each increment independently compilable.

<a id="p05-routing"></a>
## P05 — Routing

Land route selection, same-depth retention, expiry, path/TTL bounds and recovery in increments. Tests must cover gateway loss/return, equal-depth stability and stale state. No changes should globally reset unrelated working sessions.

<a id="p06-security"></a>
## P06 — Membership and security

Separate admission/state-machine changes from cryptographic adapters. Cover wrong identity, replay, reboot and capacity boundaries. Document that a shared-key member is trusted; do not claim end-to-end application security from link encryption.

<a id="p07-packets"></a>
## P07 — Packet delivery

Split wire codecs, fragment/reassembly rules, acknowledgement/retry behavior and bounded queue integration. Preserve backpressure, expiry and buffer-ownership regressions. Do not add a second independent Lab test framework to upstream.

<a id="p08-ipv4"></a>
## P08 — IPv4 adapter

Separate the DHCP codec/client, lwIP edge hooks, proxy/lease evidence and integrated ownership handover. Keep lease time independent of path changes and reject stale identity/transaction evidence. A no-WiFi boot must not assume a prior lease in RAM.

<a id="p09-ipv6-discovery"></a>
## P09 — IPv6 and discovery

Review IPv6 parsing, ND/SLAAC state and discovery publication in small steps. Address-family readiness must be independent; unspecified IPv4 is not a valid endpoint when only IPv6 is ready. Authentication and lifetime checks belong to the mesh adapter, not generic network utilities.

<a id="p10-integration"></a>
## P10 — Integration and documentation

Expose the minimal YAML and ordinary services only when dependencies are ready. Update user/developer documentation and include the supported versions, defaults and measured limitations. Complete the outstanding manual WiFi-to-mesh-to-WiFi acceptance case before calling the series merge-ready.

## How future PRs should reference this repository

Each PR description should contain the concrete problem, resulting behavior, relevant tests and upstream dependency links. Add a short context link such as:

> Part of the ESPHome mesh series, step P08. Architecture: `https://github.com/rosenrot00/esphome-mesh/blob/<commit>/docs/ARCHITECTURE.md`. Roadmap: `https://github.com/rosenrot00/esphome-mesh/blob/<commit>/docs/UPSTREAM_PLAN.md#p08-ipv4`.

Replace `<commit>` with the actual reviewed commit SHA. Do not use a changing `main` URL for evidence. Update the status table with real PR URLs and merge results as the series develops. Avoid empty draft PRs or placeholder issues created only to fill this table.
