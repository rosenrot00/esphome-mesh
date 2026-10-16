# Compatibility

The external-component alpha targets Stock ESPHome **2026.9.1** with **ESP-IDF 5.5.5**. Use all four external components: `mesh`, `network`, `wifi`, `espnow_driver`. The overlays replace bundled code from that release. Do not assume compatibility with a newer ESPHome release simply because its YAML validates.

Supported mesh targets are ESP32, S3, C3, C5 and C6. The code requires ESP-IDF >=5.5 and <6.0; the alpha pins 5.5.5. Physical qualification covers three ESP32-S3 devices; other targets have earlier native build evidence, not equivalent physical qualification. C5 mesh requires 2.4 GHz; its WiFi band AUTO/5 GHz options are rejected.

Each gateway must be on the same home LAN as other eligible gateways. Router DHCP, unicast LAN reachability and local discovery need to be allowed by the network. WiFi LIGHT is the qualified power-save option; HIGH is not qualified. PSRAM is not required.

## Ethernet gateways

Ethernet gateway support is implemented in this source, but no configuration, compilation, automated or hardware tests have been run for the change. The existing WiFi hardware evidence does not qualify this source revision.

Configure the normal ESPHome `ethernet:` section and `mesh:`. A `wifi:` section is not required. The mesh registers its radio requirement with ESP32 so Ethernet-only firmware retains ESP-NOW support. The gateway selects the Ethernet netif for DHCP relay, IPv4 proxy ARP and IPv6 neighbour handling. API, web and OTA use that same IP path.

With both `ethernet:` and `wifi:`, use Stock ESPHome's `network.priority` configuration listing both interfaces. Mesh follows that priority among connected interfaces; otherwise Ethernet takes precedence. LAN interface changes retire LAN-bound proxy evidence, not authenticated mesh sessions. Cable loss can make the node a mesh client when another gateway is reachable; Ethernet's MAC-derived IPv6 addresses are not reused as station-MAC mesh identities. Native Ethernet and mesh DHCP use different MAC identities, so the node may receive a different IPv4 address after cable loss.

Ethernet does not supply a radio channel. Set `mesh.channel` on Ethernet-only gateways to the 2.4 GHz channel used by any WiFi gateways that must communicate with them. Pure Ethernet-uplink setups can use the common default channel. An associated WiFi station still owns its AP channel. Automatic cross-channel coordination between independently connected gateways is not implemented.

[ethernet-gateway.yaml](../examples/ethernet-gateway.yaml) shows an untested ESP32-S3/W5500 example. Select the driver and pins for your own hardware. No new `network` component changes, server service, fixed IP or per-gateway key are required.

## Stock CLI for a node without WiFi

Mesh-only firmware can obtain IP connectivity from a fresh boot. However, Stock ESPHome 2026.9.1's Python Core does not recognize the new connection provider when choosing the default upload/log hostname for a YAML with no `wifi`, `ethernet` or `openthread` section. External components cannot replace that Python Core class.

Use an explicit target with Stock CLI:

```sh
esphome logs mesh-only-node.yaml --device mesh-node-c.local
esphome upload mesh-only-node.yaml --device mesh-node-c.local
```

This changes only CLI target selection; it does not require a Linux service or a fixed IP. Name discovery must be available on the local LAN. A device with a normal `wifi` block retains Stock's usual hostname selection even while firmware traffic uses mesh. Fully automatic CLI/cache recognition for no-WiFi configurations is part of [P01](UPSTREAM_PLAN.md#p01-network-providers), not a claimed Stock-dashboard feature of this alpha.

## Examples

The examples contain no PSRAM or LED assumptions and no fixed IP, peer, ID or gateway list. Set a unique `esphome.name`, use the same generated mesh key on all nodes, and configure at least one WiFi gateway. API encryption keys can be different per node; OTA uses that node's API key and requires encryption.

For initial installation use USB. Thereafter use normal ESPHome API/OTA tooling, with the explicit-target exception above. The web-server example uses the standard ESPHome frontend; it is not a throughput benchmark.
