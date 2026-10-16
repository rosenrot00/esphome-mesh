# ESPHome Mesh

Experimental ESP-NOW mesh networking for ESPHome. A device uses its native LAN connection when available and can reach the LAN through neighbouring devices when it loses that connection. API, web and OTA traffic use the IP path through the mesh. At least one reachable device needs a working WiFi or Ethernet uplink. Ethernet gateway support is implemented but has not been compiled or tested.

This is a community test repository, not an official ESPHome component. It also provides source snapshots, architecture notes and a proposed path to small upstream PRs.

## Quick start

Use **ESPHome 2026.9.1**, **ESP-IDF 5.5.5** and a supported ESP32. The examples target an ESP32-S3 with at least 4 MB flash and do not require PSRAM. Select the correct board for your device.

Add this directly to your device YAML alongside its normal `esp32`, `wifi`, `api` and `ota` configuration:

```yaml
external_components:
  - source: github://rosenrot00/esphome-mesh@v0.1.0-alpha.1
    components: [mesh, network, wifi, espnow_driver]
    refresh: never

mesh:
  key: !secret mesh_key
```

The `network`, `wifi` and `espnow_driver` components are compatibility dependencies of this alpha. Keep all four entries. The overlay is tied to the version above; current `dev` and other ESPHome releases are not qualified by this release.

1. Copy [examples/wifi-node.yaml](examples/wifi-node.yaml), use a unique name for each device, and select your board.
2. Copy [examples/secrets.example.yaml](examples/secrets.example.yaml) to `secrets.yaml` beside your YAML and replace the placeholders. Generate a random shared mesh key:
   ```sh
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Generate an API encryption key:
   ```sh
   python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
   ```
3. Use the **same mesh key** on all participants and different device names. Flash the initial firmware by USB using the normal ESPHome workflow.
4. Leave at least one node connected to your 2.4 GHz WiFi. Nodes discover peers and eligible WiFi gateways automatically. Static peer MACs, IDs, gateway lists and IP addresses are not needed for this setup.

The example also exposes **Mesh connection**, which is ON only when the usable mesh path is active and native WiFi is unavailable. It does not mean merely that neighbours can be heard.

For a cable-connected gateway, see [examples/ethernet-gateway.yaml](examples/ethernet-gateway.yaml) and the [Ethernet notes](docs/COMPATIBILITY.md#ethernet-gateways). It needs no `wifi:` section; ESP-NOW still uses the ESP32's 2.4 GHz radio. The mesh status sensor is OFF while a usable native Ethernet path is active.

To enable IPv6, keep the example's `network.enable_ipv6: true`. IPv4 remains supported. The LAN adapter obtains router DHCP leases and uses proxy ARP/IPv6 neighbour handling; it does not add a user-facing NAT subnet.

A [node without any WiFi configuration](examples/mesh-only-node.yaml) can join through the mesh from a fresh boot. See the [Stock CLI limitation](docs/COMPATIBILITY.md#stock-cli-for-a-node-without-wifi) before using that example.

## Defaults and support

- Eight mesh participants; configurable `max_nodes` from 2 to 16 in automatic key mode.
- 512-byte ESP-NOW data frames by default; no PSRAM requirement.
- `route_selection: shortest`: use a shorter path when available; retain a healthy path at equal depth. Optional `stable` also retains a longer healthy mesh path. Native WiFi takes precedence in both modes.
- ESP32, ESP32-S3, ESP32-C3, ESP32-C5 and ESP32-C6, ESP-IDF >=5.5 and <6.0. This alpha pins 5.5.5; physical tests cover three S3 boards.
- 2.4 GHz mesh. C5 5 GHz/AUTO band mode is not supported. WiFi LIGHT is qualified; HIGH is not qualified.
- Ethernet gateways use the same DHCP, ARP and IPv6 proxy paths. This implementation is untested, including cable loss/return and mixed WiFi/Ethernet operation.
- No ESP8266 mesh, TREL, LoRa, HaLow or 802.15.4 backend in this release.

One shared radio cannot promise uninterrupted service during scanning, association or gateway loss. The full manual WiFi-to-mesh-to-WiFi acceptance case remains incomplete; see [test status](docs/TESTING.md). Do not interpret the alpha tag as a production-readiness claim.

## Review and feedback

- [Architecture and boundaries](docs/ARCHITECTURE.md)
- [Upstream PR roadmap](docs/UPSTREAM_PLAN.md)
- [Compatibility and examples](docs/COMPATIBILITY.md)
- [Tests, evidence and open acceptance work](docs/TESTING.md)
- [Reproduce the upstream review snapshot](upstream/README.md)
- [Contributing and useful test reports](CONTRIBUTING.md)

The roadmap uses stable step IDs. Future PRs can link to their step and to architecture notes at an immutable commit; each PR must still explain its own change and validation. There are no upstream PRs published for this series yet.

Related community requests: [feature request #1108](https://github.com/esphome/feature-requests/issues/1108) and [Wifi Mesh discussion #3211](https://github.com/orgs/esphome/discussions/3211). This ESP-NOW prototype is independent of the Mesh-Lite and other approaches discussed there.

## License

This repository retains [ESPHome's dual license](LICENSE): C++ runtime files are GPLv3; Python and other files are MIT. See [NOTICE](NOTICE) for source provenance.
