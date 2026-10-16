#include "mesh_component.h"

#ifdef USE_MESH_AUTO
#include "mesh_auto_security_crypto.h"
#include "esphome/core/application.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include <algorithm>
#include <cstring>
#include <esp_random.h>

namespace esphome::mesh {
namespace {
const char *const TAG = "mesh.auto";
const ::mesh_auto::Mac BROADCAST{{255, 255, 255, 255, 255, 255}};
uint8_t flags_for(const AutomaticMeshState &state, bool native, bool assigned) {
  return (state.gateway ? ::mesh_auto::kGatewayCapable : 0) |
         (state.pinned && assigned ? ::mesh_auto::kPinnedNodeId : 0) |
         (state.gateway && native ? ::mesh_auto::kNativeUplink : 0);
}
}  // namespace

void MeshComponent::set_network_key(const std::array<uint8_t, 32> &key) {
  this->auto_ = std::make_unique<AutomaticMeshState>();
  this->auto_->key = key;
}

void MeshComponent::add_auto_peer_restriction(uint8_t node, const std::array<uint8_t, 6> &mac) {
  if (this->auto_ && this->auto_->peer_restriction_count < mesh_limits::MAX_PEERS)
    this->auto_->peer_restrictions[this->auto_->peer_restriction_count++] = {node, mac};
}

void MeshComponent::add_auto_identity_restriction(uint8_t node, const std::array<uint8_t, 6> &mac) {
  if (this->auto_ && this->auto_->identity_restriction_count < mesh_limits::MAX_NODES)
    this->auto_->identity_restrictions[this->auto_->identity_restriction_count++] = {node, mac};
}

bool MeshComponent::auto_neighbor_allowed_(const std::array<uint8_t, 6> &mac) const {
  const auto &state = *this->auto_;
  if (mac == this->own_mac_ || !::mesh_auto::valid_mac(mac))
    return false;
  if (state.peer_restriction_count == 0)
    return true;
  for (size_t i = 0; i < state.peer_restriction_count; ++i)
    if (state.peer_restrictions[i].mac == mac)
      return true;
  return false;
}

bool MeshComponent::auto_identity_allowed_(uint8_t node, const std::array<uint8_t, 6> &mac) const {
  if (node == 0)
    return true;  // Management-only identity, never a Core peer.
  if (node > mesh_limits::MAX_NODES || !(this->allowed_nodes_ & (1U << (node - 1))))
    return false;
  const auto &state = *this->auto_;
  // Partial manual bindings are constraints, not an automatic allow-list.
  for (size_t i = 0; i < state.identity_restriction_count; ++i) {
    const auto &restriction = state.identity_restrictions[i];
    if ((restriction.node == node || restriction.mac == mac) && (restriction.node != node || restriction.mac != mac))
      return false;
  }
  for (size_t i = 0; i < state.peer_restriction_count; ++i) {
    const auto &restriction = state.peer_restrictions[i];
    if (restriction.node != 0 && (restriction.node == node || restriction.mac == mac) &&
        (restriction.node != node || restriction.mac != mac))
      return false;
  }
  return true;
}

bool MeshComponent::auto_auth_send_(void *context, const ::mesh_auto::Mac &destination, const uint8_t *data,
                                    size_t length) {
  auto *self = static_cast<MeshComponent *>(context);
  return self->management_.send(destination, data, length, millis());
}

void MeshComponent::auto_authenticated_(void *context, const ::mesh_auto::PeerIdentity &identity) {
  auto *self = static_cast<MeshComponent *>(context);
  auto &state = *self->auto_;
  if (!self->auto_neighbor_allowed_(identity.mac))
    return;
  AutomaticMeshState::Neighbor *slot = nullptr;
  for (auto &neighbor : state.neighbors) {
    if (neighbor.used && neighbor.identity.mac == identity.mac) {
      slot = &neighbor;
      break;
    }
    if (!neighbor.used && slot == nullptr)
      slot = &neighbor;
  }
  if (slot == nullptr)
    return;
  // Callbacks record events only. Membership and radio mutation happen after
  // AuthDiscovery::receive/tick returns; neither state machine is re-entered.
  slot->identity = identity;
  slot->used = slot->verified = slot->pending = true;
}

void MeshComponent::auto_revoked_(void *context, const ::mesh_auto::Mac &mac) {
  auto *self = static_cast<MeshComponent *>(context);
  for (auto &neighbor : self->auto_->neighbors)
    if (neighbor.used && neighbor.identity.mac == mac)
      neighbor.verified = false;
}

bool MeshComponent::auto_membership_send_(void *context, const uint8_t *data, size_t length) {
  auto *self = static_cast<MeshComponent *>(context);
  if (!self->management_.ready() || length > ::mesh_membership::kMaxWireSize)
    return false;
  uint8_t wire[::mesh_transport::MAX_MANAGEMENT_SIZE];
  size_t written;
  return self->auto_->auth->seal_group(data, length, wire, sizeof(wire), written) &&
         self->management_.send(BROADCAST, wire, written, millis());
}

uint64_t MeshComponent::auto_challenge_(void *) {
  uint64_t challenge;
  do {
    esp_fill_random(&challenge, sizeof(challenge));
  } while (challenge == 0);
  return challenge;
}

void MeshComponent::auto_slot_changed_(void *context, const ::mesh_membership::SlotChange &change) {
  auto *self = static_cast<MeshComponent *>(context);
  auto &state = *self->auto_;
  auto &binding = state.bindings[change.node_id - 1];
  if (++state.next_epoch == 0)
    ++state.next_epoch;
  binding.epoch = state.next_epoch;
  binding.present = change.has_current && self->auto_identity_allowed_(change.node_id, change.current.mac);
  binding.mac = change.has_current ? change.current.mac : ::mesh_auto::Mac{};
  binding.boot = change.has_current ? change.current.boot : ::mesh_auto::BootNonce{};
  binding.session = 0;
  if (binding.present && !state.auth->identity_session_tag(binding.mac, binding.boot, binding.session))
    binding.present = false;
  binding.ready = binding.netif_done = binding.mdns_done = false;
  state.ready_mask &= uint16_t(~(1U << (change.node_id - 1)));
  self->ip_delivery_.reset_peer(change.node_id);
  // Session-bound frames and cached routes already bind every owner to its boot session.
  // Reconstructing the entire Core here would reset our advertisement sequence
  // within the same boot and interrupt unrelated, still-valid gateway paths.
  // Pending application controls have not acquired their destination session
  // yet, so discard only work addressed to the changed compact-ID owner.
  self->endpoint_challenges_.reset_peer(change.node_id);
  self->endpoint_replies_[change.node_id - 1] = 0;
#ifndef MESH_IP_CLIENT_ONLY
  self->pending_endpoint_witness_[change.node_id - 1] = {};
  self->pending_lease_results_[change.node_id - 1] = {};
  self->pending_ip_acks_[change.node_id - 1] = {};
#endif
  for (auto &pending : self->pending_probes_)
    if (pending.peer == change.node_id)
      pending = {};
  if (self->benchmark_peer_ == change.node_id)
    self->benchmark_active_ = false;
}

void MeshComponent::auto_local_changed_(void *context, uint8_t old_id, uint8_t new_id,
                                        ::mesh_membership::LocalChange reason) {
  auto *self = static_cast<MeshComponent *>(context);
  auto &state = *self->auto_;
  if (!state.quarantined)
    self->runtime_->cancel_pending();
  state.local_dirty = state.quarantined = true;
  state.reboot_id = new_id;
  state.reboot_pending = new_id != 0;
  ESP_LOGW(TAG, "IDENTITY collision old=%u new=%u reason=%u; suspend compact-ID traffic", old_id, new_id,
           static_cast<unsigned>(reason));
}

bool MeshComponent::auto_setup_() {
  auto &state = *this->auto_;
  // An intentionally Wi-Fi-disabled boot still needs a started radio both for
  // its station MAC and ESP-IDF's hardware-backed cryptographic entropy.
  if (!Esp32WifiPlatform::native_requested() || Esp32WifiPlatform::disabled()) {
    Esp32WifiPlatform::pause_native();
    Esp32WifiPlatform::ChannelBounds bounds;
    if (!Esp32WifiPlatform::start_unassociated(this->cached_channel_, bounds))
      return false;
    this->channel_search_.set_country(bounds.first, bounds.count);
    this->mesh_radio_active_ = true;
    this->last_wifi_probe_ = millis();
    ESP_LOGI(TAG, "MESH_RADIO active=YES reason=native_disabled");
  }
  if (!Esp32WifiPlatform::station_address(this->own_mac_))
    return false;
  uint8_t radio_channel;
  if (!Esp32WifiPlatform::current_channel(radio_channel))
    return false;
  state.auth = std::make_unique<::mesh_auto::AuthDiscovery>();
  state.members = std::make_unique<::mesh_membership::Membership>();
  if (!state.auth->configure(state.key, this->own_mac_, 0, flags_for(state, false, false), esp32_auto_security_crypto(),
                             {this, auto_auth_send_, auto_authenticated_, auto_revoked_}))
    return false;
  // Erase the root-key copy; the authentication engine retains its HKDF PRK.
  volatile uint8_t *secret = state.key.data();
  for (size_t i = 0; i < state.key.size(); ++i)
    secret[i] = 0;
  ::mesh_auto::Key16 pmk;
  if (!state.auth->derive_network_key(this->management_.key_context().network, pmk) ||
      !this->management_.configure_key(pmk) || !state.auth->begin(millis()))
    return false;
  uint32_t preference_key = 0x4D414931;  // Versioned, scoped to this mesh.
  for (uint8_t byte : state.auth->network_id())
    preference_key = (preference_key ^ byte) * 16777619U;
  state.preference = global_preferences->make_preference<uint8_t>(preference_key, true);
  uint8_t preferred = 0;
  if (!state.preference.load(&preferred) || preferred > mesh_limits::MAX_NODES)
    preferred = 0;
  uint16_t local_slots = this->allowed_nodes_;
  for (uint8_t id = 1; id <= mesh_limits::MAX_NODES; ++id)
    if (!this->auto_identity_allowed_(id, this->own_mac_))
      local_slots &= uint16_t(~(1U << (id - 1)));
  state.members->set_callbacks({this, auto_membership_send_, auto_challenge_, auto_slot_changed_, auto_local_changed_});
  if (!state.members->set_allowed_ids(this->allowed_nodes_) || !state.members->set_local_allowed_ids(local_slots) ||
      !state.members->begin(this->own_mac_, state.auth->boot_nonce(), preferred, state.pinned ? this->node_id_ : 0,
                            flags_for(state, false, true), millis()) ||
      state.members->local_id() == 0)
    return false;
  this->node_id_ = state.members->local_id();
  state.auth->set_local_identity(this->node_id_, flags_for(state, false, true));
  auto &own = state.bindings[this->node_id_ - 1];
  if (!own.present || own.session == 0)
    return false;
  own.ready = true;
  state.ready_mask |= uint16_t(1U << (this->node_id_ - 1));
  state.initialized = true;
  state.preference.save(&this->node_id_);
  this->ip_netif_.set_gateway_enabled(state.gateway);
  const auto &mac = this->own_mac_;
  ESP_LOGI(TAG, "IDENTITY mac=%02X:%02X:%02X:%02X:%02X:%02X node=%u automatic=%s gateway=%s", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5], this->node_id_, YESNO(!state.pinned), YESNO(state.gateway));
  return true;
}

uint64_t MeshComponent::auto_session_(void *context, ::mesh_core::NodeId node) {
  return static_cast<MeshComponent *>(context)->identity_session_(node);
}

void MeshComponent::auto_tick_(uint32_t now, bool direct) {
  auto &state = *this->auto_;
  if (!state.initialized)
    return;
  const uint32_t prior_incompatible_links = state.auth->incompatible_count();
  const uint32_t prior_incompatible_claims = state.members->counters().incompatible;
  // SDK permission is owned by the shared-PHY integration. Logical expiry
  // continues during native acquisition; no receive/transmit path can run.
  ::mesh_transport::ManagementPacket packet;
  for (size_t budget = 0; budget < 32 && this->management_.receive(packet); ++budget) {
    if (!this->auto_neighbor_allowed_(packet.source))
      continue;
    if (::mesh_auto::is_discovery_packet(packet.data, packet.length)) {
      state.auth->receive(packet.source, packet.data, packet.length, now);
    } else {
      const uint8_t *payload = nullptr;
      size_t length = 0;
      ::mesh_membership::Message message;
      if (state.auth->open_group(packet.source, packet.data, packet.length, now, payload, length) &&
          ::mesh_membership::decode_message(payload, length, message) &&
          this->auto_identity_allowed_(message.claim.node_id, message.claim.mac))
        state.members->receive(payload, length, now);
    }
  }
  state.auth->tick(now, this->management_.ready());
  for (auto &neighbor : state.neighbors) {
    if (!neighbor.used || !neighbor.pending)
      continue;
    neighbor.pending = false;
    const auto &peer = neighbor.identity;
    if (neighbor.verified && state.auth->authenticated(peer.mac, now) &&
        this->auto_identity_allowed_(peer.node_id, peer.mac))
      state.members->observe_verified({peer.mac, peer.boot_nonce, peer.node_id, peer.flags, 0, peer.protocol}, now);
  }
  state.members->set_flags(flags_for(state, direct, true));
  state.members->tick(now);
  if (state.auth->incompatible_count() != prior_incompatible_links ||
      state.members->counters().incompatible != prior_incompatible_claims)
    ESP_LOGW(TAG, "PROTOCOL admission rejected: incompatible_links=%u incompatible_claims=%u",
             static_cast<unsigned>(state.auth->incompatible_count()),
             static_cast<unsigned>(state.members->counters().incompatible));
  const uint8_t local_id = state.members->local_id();
  state.auth->set_local_identity(local_id, flags_for(state, direct, local_id != 0));
  if (state.quarantined) {
    this->core_->set_direct_uplink(false, now);
    this->ip_netif_.set_gateway_enabled(false);
    this->ip_netif_.select_gateway(0);
    this->ip_netif_.clear_mesh_lease();
    return;
  }
  // Session changes invalidate only routes/frames that refer to that owner.
  // Peer rebinding below retains other radio queues and the Core's own serials.
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    auto &binding = state.bindings[node - 1];
    if (node == this->node_id_ || binding.epoch == 0 || binding.ready)
      continue;
    // Remove the encrypted old-owner mapping before admitting the replacement.
    if (!this->management_.remove_peer(node))
      continue;
    const uint8_t *mac = binding.present ? binding.mac.data() : nullptr;
    if (!binding.netif_done)
      binding.netif_done = this->ip_netif_.update_peer_identity(node, mac, binding.epoch);
#ifdef USE_MESH_DISCOVERY
    if (!binding.mdns_done)
      binding.mdns_done = this->ip_mdns_.update_peer_identity(node, mac, binding.epoch);
#else
    binding.mdns_done = true;
#endif
    if (binding.netif_done && binding.mdns_done) {
      binding.ready = true;
      if (binding.present)
        state.ready_mask |= uint16_t(1U << (node - 1));
      ESP_LOGI(TAG, "MEMBER node=%u mac=%02X:%02X:%02X:%02X:%02X:%02X admitted=%s epoch=%u", node, binding.mac[0],
               binding.mac[1], binding.mac[2], binding.mac[3], binding.mac[4], binding.mac[5], YESNO(binding.present),
               static_cast<unsigned>(binding.epoch));
    }
  }
  // An authentication may describe the old compact ID while collision gossip
  // converges. Only the registry's freshly verified current owner is bound.
  for (auto &neighbor : state.neighbors) {
    if (!neighbor.used)
      continue;
    const auto &identity = neighbor.identity;
    const bool authenticated = neighbor.verified && state.auth->authenticated(identity.mac, now);
    const auto *member = state.members->find(identity.mac);
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
      std::array<uint8_t, 6> mapped;
      if (this->management_.peer_address(node, mapped) && mapped == identity.mac &&
          (!authenticated || member == nullptr || member->node_id != node || member->boot != identity.boot_nonce ||
           !this->allowed_(node)))
        this->management_.remove_peer(node);
    }
    if (!authenticated) {
      bool still_bound = false;
      for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
        std::array<uint8_t, 6> mapped;
        still_bound |= this->management_.peer_address(node, mapped) && mapped == identity.mac;
      }
      if (!still_bound)
        neighbor = {};
      continue;
    }
    if (member == nullptr || member->node_id == 0 || member->boot != identity.boot_nonce ||
        !this->allowed_(member->node_id))
      continue;
    std::array<uint8_t, 6> mapped;
    if (this->management_.peer_address(member->node_id, mapped) && mapped == identity.mac)
      continue;
    ::mesh_auto::Key16 lmk;
    if (state.auth->derive_session_key(identity, this->management_.key_context().session, lmk) &&
        this->management_.install_peer(member->node_id, identity.mac, lmk))
      ESP_LOGI(TAG, "LINK node=%u encrypted=YES", member->node_id);
  }
  if (now - state.last_status >= 5000) {
    state.last_status = now;
    const auto &mac = this->own_mac_;
    ESP_LOGI(
        TAG,
        "AUTO node=%u mac=%02X:%02X:%02X:%02X:%02X:%02X members=0x%04X ready=0x%04X authenticated=%u gateways=0x%04X",
        this->node_id_, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], state.members->member_mask(), state.ready_mask,
        static_cast<unsigned>(state.auth->authenticated_count(now)), this->known_gateway_mask_());
  }
}

void MeshComponent::auto_loop_() {
  if (!this->auto_)
    return;
  uint8_t next = 0;
  xSemaphoreTakeRecursive(this->mutex_, portMAX_DELAY);
  if (this->auto_->reboot_pending)
    next = this->auto_->reboot_id;
  xSemaphoreGiveRecursive(this->mutex_);
  if (next == 0)
    return;
  // Relocating a local IP endpoint across lwIP/netif lifetimes is deliberately
  // a clean restart. The public MAC identity and LAN DHCP address stay stable.
  if (this->auto_->preference.save(&next) && global_preferences->sync()) {
    ESP_LOGW(TAG, "IDENTITY persist compact address=%u and restart", next);
    App.safe_reboot();
  }
}

}  // namespace esphome::mesh
#endif
