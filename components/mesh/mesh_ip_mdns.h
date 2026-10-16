#pragma once

#include "mesh_limits.h"

#include "esphome/core/defines.h"
#ifdef USE_MESH_DISCOVERY
#include "mesh_ip_discovery.h"
#include "mesh_ip_netif.h"
#include "esphome/components/mdns/mdns_component.h"

#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

namespace esphome::mesh {

// All ESP-IDF mDNS calls and bounded metadata updates run in the main loop. The
// mesh worker only queues bounded control chunks and reads atomic flags.
class MeshIpMdns {
 public:
  void set_component(mdns::MDNSComponent *component) { this->component_ = component; }
  void authorize(uint8_t node, const uint8_t *mac) {
#ifndef MESH_IP_CLIENT_ONLY
    this->registry_.authorize(node, mac);
#else
    (void) node;
    (void) mac;
#endif
  }
  void setup();
  // Worker request/main-loop acknowledgment. Retrying an identical nonzero
  // epoch is idempotent; a new boot session uses a new epoch even at the same
  // MAC. True only after old delegated ownership and metadata are gone.
  bool update_peer_identity(uint8_t node, const uint8_t *mac, uint32_t identity_epoch);
  bool local_descriptor(uint8_t *output, size_t capacity, size_t &written);
  void enqueue(uint8_t node, const uint8_t *data, size_t length);
  // Call only after the gateway accepted an authenticated IP_STATUS through
  // MeshIpNetif::set_peer. DATA and other controls never renew discovery.
  void note_status(uint8_t node, uint32_t address, bool fallback);
#ifdef MESH_IPV6
  void note_ipv6_status(uint8_t node, const ::mesh_ip::Ipv6AddressSnapshot &snapshot);
#endif
  void loop(::mesh_ip::MeshIpNetif &netif, bool gateway);
  bool announced(uint8_t node) const {
#ifndef MESH_IP_CLIENT_ONLY
    return node >= 1 && node <= mesh_limits::MAX_NODES && this->published_[node - 1].load();
#else
    (void) node;
    return false;
#endif
  }
  void shutdown();

 private:
  bool ready_() const;
  mdns::MDNSComponent *component_{nullptr};
#ifndef MESH_IP_CLIENT_ONLY
  struct Chunk {
    uint8_t node{0}, length{0};
    uint32_t epoch{0};
    uint8_t data[::mesh_ip::DISCOVERY_FRAME_MAX]{};
  };
  struct Published {
    std::array<char, 64> hostname{};
    uint32_t revision{0}, address{0};
#ifdef MESH_IPV6
    ::mesh_ip::Ipv6AddressSnapshot ipv6{};  // Main-loop-owned published set.
#endif
    bool api{false}, http{false}, removal_pending{false};
  };
  struct Status {
    std::atomic<uint32_t> generation{0}, address{0}, seen{0};
    std::atomic<uint32_t> epoch{0};
    uint32_t consumed{0}, consumed_epoch{0};  // Main loop only.
#ifdef MESH_IPV6
    std::atomic<bool> ipv6_active{false};
    std::atomic<uint32_t> ipv6_seen{0};
#endif
  };
  bool publish_(uint8_t node, uint32_t address, const ::mesh_ip::DiscoveryDescriptor &descriptor,
                ::mesh_ip::MeshIpNetif &netif);
#ifdef MESH_IPV6
  bool collect_ipv6_(uint8_t node, ::mesh_ip::MeshIpNetif &netif, ::mesh_ip::Ipv6AddressSnapshot &snapshot) const;
#endif
  bool withdraw_(uint8_t node);
  void apply_identity_changes_();
  bool identity_current_(uint8_t node) const;
  struct IdentityRequest {
    std::atomic<uint32_t> generation{0}, low{0}, high{0}, epoch{0}, applied{0};
  };
  IdentityRequest identities_[mesh_limits::MAX_NODES]{};
  ::mesh_ip::DiscoveryRegistry registry_;
  Published records_[mesh_limits::MAX_NODES]{};
  std::atomic<bool> published_[mesh_limits::MAX_NODES]{};
  Status statuses_[mesh_limits::MAX_NODES]{};
  StaticQueue_t queue_storage_{};
  uint8_t queue_buffer_[8 * sizeof(Chunk)]{};
  QueueHandle_t queue_{nullptr};
  uint32_t last_loop_{0}, retry_after_[mesh_limits::MAX_NODES]{};
#endif
};
}  // namespace esphome::mesh
#endif
