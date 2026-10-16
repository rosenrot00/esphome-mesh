#pragma once

#include "mesh_limits.h"

#include "mesh_auto_security.h"
#include "mesh_membership.h"
#include "esphome/core/preferences.h"
#include <memory>

namespace esphome::mesh {

// Platform integration state. Identity/authentication remain portable modules;
// compact IDs are only local routing addresses, never device credentials.
struct AutomaticMeshState {
  using Mac = ::mesh_auto::Mac;
  using Boot = ::mesh_auto::BootNonce;
  struct Restriction {
    uint8_t node{0};
    Mac mac{};
  };
  struct Binding {
    uint64_t session{0};
    uint32_t epoch{0};
    Mac mac{};
    Boot boot{};
    bool present{false}, ready{false}, netif_done{false}, mdns_done{false};
  };
  struct Neighbor {
    ::mesh_auto::PeerIdentity identity{};
    bool used{false}, verified{false}, pending{false};
  };
  ::mesh_auto::Key32 key{};
  std::unique_ptr<::mesh_auto::AuthDiscovery> auth;
  std::unique_ptr<::mesh_membership::Membership> members;
  ESPPreferenceObject preference;
  Restriction peer_restrictions[mesh_limits::MAX_PEERS]{}, identity_restrictions[mesh_limits::MAX_NODES]{};
  size_t peer_restriction_count{0}, identity_restriction_count{0};
  Binding bindings[mesh_limits::MAX_NODES]{};
  Neighbor neighbors[mesh_limits::MAX_PEERS]{};
  uint16_t ready_mask{0};
  uint32_t next_epoch{0}, last_status{0};
  bool pinned{false}, gateway{true}, initialized{false};
  bool local_dirty{false}, quarantined{false}, reboot_pending{false};
  uint8_t reboot_id{0};
};

}  // namespace esphome::mesh
