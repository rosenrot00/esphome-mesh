#include "mesh_ip_netif.h"
#include "mesh_ip_dhcp.h"

#include <algorithm>
#include <cstring>
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <esp_timer.h>
#include <freertos/task.h>
#include <lwip/etharp.h>
#include <lwip/def.h>
#include <lwip/ip4.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#ifdef MESH_HAS_ETHERNET
#include <netif/ethernet.h>
#endif

namespace mesh_ip {

MeshIpNetif *MeshIpNetif::instance_ = nullptr;

static uint32_t now_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }
#ifndef MESH_IP_CLIENT_ONLY
static uint32_t now_seconds() { return static_cast<uint32_t>(esp_timer_get_time() / 1000000); }
#endif
static uint16_t read_be16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
static uint32_t read_address(const uint8_t *p) {
  uint32_t address;
  std::memcpy(&address, p, 4);
  return address;
}
#ifndef MESH_IP_CLIENT_ONLY
struct PbufPacketView {
  struct pbuf *packet;
  uint16_t offset, length;
};
static bool read_pbuf_packet(const void *context, size_t offset, uint8_t *output, size_t count) {
  const auto &view = *static_cast<const PbufPacketView *>(context);
  if (offset > view.length || count > view.length - offset)
    return false;
  return pbuf_copy_partial(view.packet, output, static_cast<uint16_t>(count),
                           static_cast<uint16_t>(view.offset + offset)) == count;
}
#endif

bool MeshIpNetif::configure(uint8_t node_id, uint8_t gateway_id, bool require_dhcp, uint16_t gateway_candidates) {
  if (this->configured_.load())
    return this->node_id_ == node_id && this->gateway_id_ == gateway_id && this->require_dhcp_ == require_dhcp &&
           this->gateway_candidates_ == gateway_candidates;
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || gateway_id == 0 || gateway_id > mesh_limits::MAX_NODES ||
      (instance_ != nullptr && instance_ != this))
    return false;
  if (gateway_candidates != 0 && (gateway_candidates & (1U << (gateway_id - 1))) == 0)
    return false;
#ifdef MESH_IP_CLIENT_ONLY
  if (node_id == gateway_id || (gateway_candidates & (1U << (node_id - 1))) != 0)
    return false;
#elif defined(MESH_IP_GATEWAY_ONLY)
  if (node_id != gateway_id)
    return false;
#endif
  this->node_id_ = node_id;
  this->require_dhcp_ = require_dhcp;
  this->gateway_candidates_ = gateway_candidates;
  this->gateway_id_ = gateway_id;
  this->rx_queue_ = xQueueCreateStatic(RX_CAPACITY, sizeof(IpPacket), this->rx_buffer_, &this->rx_storage_);
#ifndef MESH_IP_CLIENT_ONLY
  this->arp_queue_ = xQueueCreateStatic(ARP_CAPACITY, sizeof(ArpRequest), this->arp_buffer_, &this->arp_storage_);
  this->probe_request_queue_ = xQueueCreateStatic(PROBE_QUEUE_CAPACITY, sizeof(LeaseProbeResult),
                                                  this->probe_request_buffer_, &this->probe_request_storage_);
  this->probe_result_queue_ = xQueueCreateStatic(PROBE_QUEUE_CAPACITY, sizeof(LeaseProbeResult),
                                                 this->probe_result_buffer_, &this->probe_result_storage_);
#endif
  instance_ = this;
  this->configured_.store(true);
  this->schedule_();
  return true;
}

bool MeshIpNetif::role_current_() const {
  const uint8_t gateway = this->gateway_id_.load();
  return this->transport_current_() && gateway != 0 && (gateway == this->node_id_ || this->peer_current_(gateway));
}

bool MeshIpNetif::peer_epoch_current_(uint8_t node_id, uint32_t epoch) const {
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES)
    return false;
  const auto &request = this->identity_requests_[node_id - 1];
  const uint32_t revision = request.revision.load();
  return (revision & 1) == 0 && request.epoch.load() == epoch && request.applied.load() == epoch &&
         (epoch == 0 || request.low.load() != 0 || request.high.load() != 0) && request.revision.load() == revision;
}

bool MeshIpNetif::peer_current_(uint8_t node_id) const {
  return node_id != 0 && node_id <= mesh_limits::MAX_NODES &&
         this->peer_epoch_current_(node_id, this->identity_requests_[node_id - 1].epoch.load());
}

bool MeshIpNetif::transport_current_() const {
#ifdef MESH_HAS_ETHERNET
  const uint32_t revision = this->native_uplink_revision_.load();
  if ((revision & 1U) != 0 || revision != this->applied_native_uplink_revision_.load() ||
      revision != this->native_uplink_revision_.load())
    return false;
#endif
  const uint32_t generation = this->gateway_generation_.load();
  return (generation & 1) == 0 && this->applied_generation_.load() == generation &&
         this->gateway_generation_.load() == generation;
}

bool MeshIpNetif::candidate_(uint8_t node_id) const {
  return node_id != 0 && node_id <= mesh_limits::MAX_NODES && (this->gateway_candidates_ & (1U << (node_id - 1))) != 0;
}

bool MeshIpNetif::gateway_active_() const {
  if (!this->gateway_enabled_.load() || !this->transport_current_())
    return false;
  if (this->gateway_candidates_ != 0)
    return this->configured_.load() && this->candidate_(this->node_id_) && this->station_connected_.load();
  return this->role_current_() && this->node_id_ == this->gateway_id_.load() && this->station_connected_.load();
}

bool MeshIpNetif::select_gateway(uint8_t gateway_id) {
  if (!this->configured_.load() || gateway_id > mesh_limits::MAX_NODES)
    return false;
  if (this->gateway_candidates_ != 0 && gateway_id != 0 && !this->candidate_(gateway_id))
    return false;
#ifdef MESH_IP_CLIENT_ONLY
  if (gateway_id == this->node_id_)
    return false;
#elif defined(MESH_IP_GATEWAY_ONLY)
  if (gateway_id != 0 && gateway_id != this->node_id_)
    return false;
#endif
  if (this->gateway_id_.load() == gateway_id)
    return true;
  // The mesh worker is the sole selector. Odd generations close all gateway
  // hooks before publishing a new ID; the TCP/IP worker alone clears state and
  // acknowledges an even generation. Driver packets carry that same epoch.
  this->gateway_generation_.fetch_add(1);
  this->applied_generation_.store(0);
  this->gateway_id_.store(gateway_id);
  if (this->gateway_candidates_ == 0) {
    this->mesh_path_validated_.store(false);
    this->available_.store(false);
    this->fallback_active_.store(false);
  }
  this->gateway_generation_.fetch_add(1);
  this->schedule_();
  return true;
}

#ifndef MESH_IP_CLIENT_ONLY
void MeshIpNetif::reset_peer_identity_state_(size_t i) {
#ifdef MESH_IPV6
  this->reset_ipv6_peer_(i);
#endif
  Peer &peer = this->peers_[i];
  peer.fallback.store(false);
  peer.endpoint.store(false);
  peer.generation.store(0);
  peer.lease_id.store(0);
  peer.lease_started.store(0);
  peer.lease_seconds.store(0);
  peer.identity_known.store(false);
  peer.desired_address.store(0);
  peer.desired_xid.store(0);
  peer.ip.store(0);
  peer.seen.store(0);
  peer.announced = false;
  peer.last_announcement = 0;
  DhcpTransaction &transaction = this->dhcp_transactions_[i];
  transaction.generation.store(0);
  transaction.xid.store(0);
  transaction.seen.store(0);
  transaction.request_type.store(0);
  transaction.mac_low.store(0);
  transaction.mac_high.store(0);
  transaction.candidate_xid.store(0);
  transaction.candidate_address.store(0);
  LeaseProbe &probe = this->lease_probes_[i];
  probe.phase.store(0);
  probe.address.store(0);
  probe.conflict.store(false);
  probe.nonce = probe.last_probe = probe.completed = probe.generation = probe.peer_epoch = 0;
  probe.attempts = 0;
  DhcpOwnership &ownership = this->dhcp_ownership_[i];
  // A newly elected gateway must observe its own authenticated DHCP ACK.
  // An old client heartbeat alone never establishes LAN address ownership.
  ownership.managed.store(true);
  ownership.local.store(false);
  ownership.active.store(false);
  ownership.revoked.store(false);
  ownership.generation.store(0);
  ownership.address.store(0);
  ownership.xid.store(0);
  ownership.seconds.store(0);
  ownership.started.store(0);
  ownership.revoked_xid.store(0);
  ownership.revoked_lease_xid.store(0);
  RemoteWitness &remote = this->remote_witnesses_[i];
  remote.active.store(false);
  remote.generation.store(0);
  remote.address.store(0);
  remote.xid.store(0);
  remote.seconds.store(0);
  remote.started.store(0);
}
#endif

bool MeshIpNetif::apply_gateway_change_(uint32_t generation) {
  if ((generation & 1) != 0 || generation != this->gateway_generation_.load())
    return false;
#ifndef MESH_IP_CLIENT_ONLY
  // A driver may have entered before select_gateway closed its gate. Never
  // erase its DHCP snapshots while it is still publishing.
  if (this->driver_tx_busy_.exchange(true))
    return false;
#endif
  if (generation != this->gateway_generation_.load()) {
#ifndef MESH_IP_CLIENT_ONLY
    this->driver_tx_busy_.store(false);
#endif
    return false;
  }
  portENTER_CRITICAL(&this->tx_lock_);
  this->tx_flows_.reset();
  portEXIT_CRITICAL(&this->tx_lock_);
  this->rx_pending_ = false;
  xQueueReset(this->rx_queue_);
#ifndef MESH_IP_CLIENT_ONLY
  xQueueReset(this->arp_queue_);
  xQueueReset(this->probe_request_queue_);
  xQueueReset(this->probe_result_queue_);
  if (this->gateway_candidates_ != 0 && generation != 2) {
    for (LeaseProbe &probe : this->lease_probes_)
      probe.phase.store(0);  // Retry an unfinished initial probe in this epoch.
  }
  if ((generation != 2 || this->require_dhcp_ || this->gateway_candidates_ != 0) &&
      (this->gateway_candidates_ == 0 || generation == 2)) {
    for (size_t i = 0; i < mesh_limits::MAX_NODES; i++)
      this->reset_peer_identity_state_(i);
  }
  this->driver_tx_busy_.store(false);
#endif
  if (generation != this->gateway_generation_.load())
    return false;
  this->applied_generation_.store(generation);
  return true;
}

bool MeshIpNetif::apply_pending_identities_() {
  const uint16_t pending = this->identity_pending_mask_.load();
  if (pending == 0)
    return true;
#ifndef MESH_IP_CLIENT_ONLY
  if (this->driver_tx_busy_.exchange(true))
    return false;
#endif
  for (size_t i = 0; i < mesh_limits::MAX_NODES; ++i) {
    const uint16_t bit = 1U << i;
    if ((pending & bit) == 0)
      continue;
    auto &request = this->identity_requests_[i];
    const uint32_t revision = request.revision.load();
    if ((revision & 1) != 0)
      continue;
    const uint32_t epoch = request.epoch.load(), low = request.low.load(), high = request.high.load();
    if (request.revision.load() != revision)
      continue;
    if (request.applied.load() != epoch) {
#ifndef MESH_IP_CLIENT_ONLY
      // Only this owner changes: unrelated packet queues, grants and the local
      // interface remain live. Driver snapshots are excluded during the reset.
      this->reset_peer_identity_state_(i);
      this->dhcp_peer_macs_[i].low.store(low);
      this->dhcp_peer_macs_[i].high.store(high);
      if (low != 0 || high != 0)
        this->dhcp_peer_mac_mask_.fetch_or(bit);
      else
        this->dhcp_peer_mac_mask_.fetch_and(static_cast<uint16_t>(~bit));
#else
      (void) low;
      (void) high;
#endif
    }
    if (request.revision.load() != revision)
      continue;
    request.applied.store(epoch);
    this->identity_pending_mask_.fetch_and(static_cast<uint16_t>(~bit));
    // A newer publication may race the mask clear. Its revision must stay
    // pending even if it had already set this same bit.
    if (request.revision.load() != revision)
      this->identity_pending_mask_.fetch_or(bit);
  }
#ifndef MESH_IP_CLIENT_ONLY
  this->driver_tx_busy_.store(false);
#endif
  return this->identity_pending_mask_.load() == 0;
}

void MeshIpNetif::update(uint32_t ip, uint32_t mask, uint32_t gateway, bool connected, bool reachable,
                         NativeUplink uplink) {
  if (!this->configured_.load())
    return;
#ifdef MESH_HAS_ETHERNET
  if (uplink != this->native_uplink_.load()) {
    this->native_uplink_revision_.fetch_add(1);
    this->native_uplink_.store(uplink);
    this->native_uplink_revision_.fetch_add(1);
  }
#else
  (void) uplink;
#endif
  if (this->require_dhcp_ && !connected && this->station_connected_.load()) {
    // Native DHCP ownership is not proof at another gateway, even when the
    // routing root itself did not change during this local Wi-Fi outage.
    this->mesh_path_validated_.store(false);
    this->available_.store(false);
    this->fallback_active_.store(false);
  }
  if (ip != 0 && connected) {
    this->mesh_lease_.store(false);
    this->address_.store(ip);
    this->mask_.store(mask);
    this->gateway_.store(gateway);
  }
  this->station_connected_.store(connected);
  this->mesh_reachable_.store(reachable);
  this->schedule_();
}

bool MeshIpNetif::set_dhcp_peer_mac(uint8_t node_id, const uint8_t *mac) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) mac;
  return false;
#else
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || mac == nullptr ||
      (mac[0] & 1) != 0)
    return false;
  bool nonzero = false;
  for (size_t i = 0; i < 6; i++)
    nonzero |= mac[i] != 0;
  if (!nonzero)
    return false;
  // Setup-only configuration; immutable once the mesh worker can receive data.
  uint32_t low = 0, high = 0;
  std::memcpy(&low, mac, 4);
  std::memcpy(&high, mac + 4, 2);
  this->dhcp_peer_macs_[node_id - 1].low.store(low);
  this->dhcp_peer_macs_[node_id - 1].high.store(high);
  this->dhcp_peer_mac_mask_.fetch_or(1U << (node_id - 1));
  return true;
#endif
}

bool MeshIpNetif::update_peer_identity(uint8_t node_id, const uint8_t *mac, uint32_t identity_epoch) {
  if (!this->configured_.load() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      identity_epoch == 0)
    return false;
  uint32_t low = 0, high = 0;
  if (mac != nullptr) {
    if ((mac[0] & 1) != 0)
      return false;
    std::memcpy(&low, mac, 4);
    std::memcpy(&high, mac + 4, 2);
    if (low == 0 && high == 0)
      return false;
  }
  auto &request = this->identity_requests_[node_id - 1];
  if (request.epoch.load() == identity_epoch) {
    if (request.low.load() != low || request.high.load() != high)
      return false;
    const bool applied = request.applied.load() == identity_epoch && this->transport_current_();
    if (!applied)
      this->schedule_();  // Retry a busy driver or full TCP/IP mailbox.
    return applied;
  }
  // Close this peer before changing its identity. The route epoch belongs to
  // gateway changes; a different member must not disconnect a valid client.
  request.revision.fetch_add(1);
  if (node_id == this->gateway_id_.load()) {
    // The local lease survives a remote identity change, but a different
    // gateway owner must freshly prove its authority over that client path.
    this->mesh_path_validated_.store(false);
    this->fallback_active_.store(false);
    if (!this->station_connected_.load())
      this->available_.store(false);
  }
#ifndef MESH_IP_CLIENT_ONLY
  this->dhcp_peer_mac_mask_.fetch_and(static_cast<uint16_t>(~(1U << (node_id - 1))));
#endif
  request.low.store(low);
  request.high.store(high);
  request.epoch.store(identity_epoch);
  request.revision.fetch_add(1);
  this->identity_pending_mask_.fetch_or(1U << (node_id - 1));
  this->schedule_();
  return false;
}

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::dhcp_peer_mac_(uint8_t node_id, uint8_t output[6]) const {
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || output == nullptr || !this->transport_current_() ||
      !this->peer_current_(node_id) || (this->dhcp_peer_mac_mask_.load() & (1U << (node_id - 1))) == 0)
    return false;
  const uint32_t generation = this->gateway_generation_.load();
  const auto &peer = this->dhcp_peer_macs_[node_id - 1];
  const uint32_t low = peer.low.load(), high = peer.high.load();
  std::memcpy(output, &low, 4);
  std::memcpy(output + 4, &high, 2);
  return this->gateway_generation_.load() == generation && this->transport_current_() && this->peer_current_(node_id) &&
         (this->dhcp_peer_mac_mask_.load() & (1U << (node_id - 1))) != 0;
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::gateway_lease_valid_(uint8_t node_id, uint32_t address) const {
  if (!this->peer_current_(node_id))
    return false;
  const DhcpOwnership &ownership = this->dhcp_ownership_[node_id - 1];
  if (!ownership.managed.load())
    return true;  // Preserve the separate short-outage legacy experiment.
  if (!ownership.active.load() || ownership.revoked.load())
    return false;
  const uint32_t generation = ownership.generation.load();
  if (generation == 0 || (generation & 1) != 0 || ownership.address.load() != address)
    return false;
  const uint32_t lifetime = ownership.seconds.load(), started = ownership.started.load();
  const uint32_t now = now_seconds();
  return ownership.generation.load() == generation && ownership.active.load() &&
         (lifetime == UINT32_MAX || uint32_t(now - started) < lifetime);
}

bool MeshIpNetif::gateway_source_valid_(uint8_t node_id, uint32_t address) const {
  if (!this->gateway_active_() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      !this->peer_current_(node_id))
    return false;
  const Peer &peer = this->peers_[node_id - 1];
  const uint32_t seen = peer.seen.load();
  const uint32_t now = now_ms();
  return peer.ip.load() == address && address != 0 && uint32_t(now - seen) < PEER_LEASE_MS &&
         this->valid_peer_address_(node_id, address) &&
         (this->gateway_candidates_ == 0 ? this->gateway_lease_valid_(node_id, address)
                                         : (peer.fallback.load() && this->endpoint_lease_valid_(node_id, address)));
}

bool MeshIpNetif::witness_remaining_(uint8_t node_id, uint32_t address, uint32_t xid, uint32_t &remaining) const {
  if (!this->peer_current_(node_id))
    return false;
  const DhcpOwnership &local = this->dhcp_ownership_[node_id - 1];
  if ((local.revoked.load() || this->gateway_candidates_ != 0) &&
      (local.revoked_xid.load() == xid || local.revoked_lease_xid.load() == xid))
    return false;
  remaining = UINT32_MAX;
  bool found = false;
  // Both independent observations of the same ACK bound the same hard lease.
  // Even an expired matching observation is a fence, never a reason to take
  // a later replay's longer deadline instead.
  const auto read = [&](const auto &witness) {
    const uint32_t generation = witness.generation.load();
    if (generation == 0 || (generation & 1) != 0)
      return generation == 0;
    const uint32_t ip = witness.address.load(), token = witness.xid.load();
    if (ip != address || token != xid)
      return witness.generation.load() == generation;
    const uint32_t lifetime = witness.seconds.load(), started = witness.started.load();
    const uint32_t elapsed = uint32_t(now_seconds() - started);
    if (!witness.active.load() || (lifetime != UINT32_MAX && elapsed >= lifetime) ||
        witness.generation.load() != generation)
      return false;
    remaining = std::min(remaining, lifetime == UINT32_MAX ? UINT32_MAX : lifetime - elapsed);
    found = true;
    return true;
  };
  return read(local) && read(this->remote_witnesses_[node_id - 1]) && found;
}

bool MeshIpNetif::endpoint_lease_valid_(uint8_t node_id, uint32_t address) const {
  if (!this->peer_current_(node_id))
    return false;
  const Peer &peer = this->peers_[node_id - 1];
  const uint32_t generation = peer.generation.load();
  if (generation == 0 || (generation & 1) != 0 || !peer.endpoint.load() || peer.ip.load() != address)
    return false;
  const uint32_t lifetime = peer.lease_seconds.load(), started = peer.lease_started.load();
  return (lifetime == UINT32_MAX || uint32_t(now_seconds() - started) < lifetime) &&
         peer.generation.load() == generation && peer.endpoint.load();
}
#endif

bool MeshIpNetif::submit_dhcp_request(const uint8_t *packet, size_t length) {
  const uint32_t generation = this->gateway_generation_.load();
  DhcpMessage message;
  if (!this->configured_.load() || !this->role_current_() || this->node_id_ == this->gateway_id_ ||
      !parse_dhcp_request(packet, length, message) ||
      (message.source != 0 && lwip_ntohl(message.source) != this->address_.load())) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  const uint8_t destination = this->gateway_id_.load();
  if (destination == 0 || destination > mesh_limits::MAX_NODES)
    return false;
  const uint32_t peer_epoch = this->identity_requests_[destination - 1].epoch.load();
  IpFlowQueue::Reservation reservation;
  IpPacket *outgoing = this->reserve_outgoing_(IpFlowQueue::classify(destination, packet, length), reservation);
  if (outgoing == nullptr) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  outgoing->generation = generation;
  outgoing->destination = destination;
  outgoing->peer_epoch = peer_epoch;
  outgoing->ingress_source = 0;
  outgoing->ingress_epoch = 0;
  outgoing->gateway_ingress = false;
  outgoing->length = length;
  std::memcpy(outgoing->data, packet, length);
  if (!this->commit_outgoing_(reservation)) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  this->mesh_tx_.fetch_add(1);
  return true;
}

bool MeshIpNetif::install_valid_lease(uint32_t ip, uint32_t mask, uint32_t gateway) {
  const uint32_t host_mask = ~lwip_ntohl(mask);
  const uint32_t host_part = lwip_ntohl(ip) & host_mask;
  if (!this->configured_.load() || !this->role_current_() || this->node_id_ == this->gateway_id_ ||
      !unicast_address_(ip) || mask == 0 || host_mask == 0 || (host_mask & (host_mask + 1)) != 0 || host_part == 0 ||
      host_part == host_mask || !unicast_address_(gateway) || (gateway & mask) != (ip & mask) || gateway == ip)
    return false;
  this->address_.store(ip);
  this->mask_.store(mask);
  this->gateway_.store(gateway);
  this->mesh_lease_.store(true);
  this->mesh_path_validated_.store(true);
  this->schedule_();
  return true;
}

void MeshIpNetif::clear_mesh_lease() {
  if (this->configured_.load() && this->node_id_ != this->gateway_id_) {
    // Explicit withdrawal also clears a cached native-STA address when root
    // switches from the historical short-outage path to managed mesh DHCP.
    this->mesh_lease_.store(false);
    this->mesh_path_validated_.store(false);
    this->address_.store(0);
    this->mask_.store(0);
    this->gateway_.store(0);
    this->available_.store(false);
    this->fallback_active_.store(false);
    this->ready_.store(false);
    this->schedule_();
  }
}

bool MeshIpNetif::begin_lease_probe(uint8_t node_id, uint32_t address, uint32_t nonce) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) nonce;
  return false;
#else
  if (!this->configured_.load() || !this->gateway_active_() || !this->valid_peer_address_(node_id, address))
    return false;
  const DhcpTransaction &transaction = this->dhcp_transactions_[node_id - 1];
  const uint32_t generation = transaction.generation.load();
  if (generation == 0 || (generation & 1) != 0 || transaction.xid.load() != nonce ||
      uint32_t(now_ms() - transaction.seen.load()) >= DHCP_TRANSACTION_MS ||
      transaction.candidate_xid.load() != nonce || transaction.candidate_address.load() != address ||
      transaction.generation.load() != generation || !this->gateway_lease_valid_(node_id, address))
    return false;
  LeaseProbeResult request;
  request.node_id = node_id;
  request.address = address;
  request.nonce = nonce;
  request.generation = this->gateway_generation_.load();
  request.peer_epoch = this->identity_requests_[node_id - 1].epoch.load();
  if (xQueueSend(this->probe_request_queue_, &request, 0) != pdTRUE) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  this->schedule_();
  return true;
#endif
}

bool MeshIpNetif::pop_probe_result(LeaseProbeResult &result) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) result;
  return false;
#else
  if (this->probe_result_queue_ == nullptr || !this->gateway_active_())
    return false;
  while (xQueueReceive(this->probe_result_queue_, &result, 0) == pdTRUE) {
    if (result.generation == this->gateway_generation_.load() &&
        this->peer_epoch_current_(result.node_id, result.peer_epoch) &&
        this->gateway_lease_valid_(result.node_id, result.address))
      return true;
  }
  return false;
#endif
}

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::valid_dhcp_request_(uint8_t source, const uint8_t *packet, size_t length) const {
  DhcpMessage message;
  uint8_t mac[6]{};
  return source != 0 && source <= mesh_limits::MAX_NODES && source != this->node_id_ &&
         this->dhcp_peer_mac_(source, mac) && parse_dhcp_request(packet, length, message) &&
         std::memcmp(message.mac, mac, 6) == 0 &&
         (message.source == 0 || this->valid_peer_address_(source, lwip_ntohl(message.source)));
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::track_dhcp_request_(uint8_t source, const uint8_t *packet, size_t length) {
  DhcpMessage message;
  if (!parse_dhcp_request(packet, length, message))
    return false;
  if (this->driver_tx_busy_.exchange(true)) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  DhcpTransaction &transaction = this->dhcp_transactions_[source - 1];
  DhcpOwnership &ownership = this->dhcp_ownership_[source - 1];
  ownership.managed.store(true);
  if (message.type == 1 || message.type == 4 || message.type == 7) {
    ownership.active.store(false);
    this->peers_[source - 1].fallback.store(false);
    this->peers_[source - 1].endpoint.store(false);
    this->remote_witnesses_[source - 1].active.store(false);
    if (message.type != 1) {
      ownership.revoked_xid.store(message.xid);
      ownership.revoked_lease_xid.store(this->peers_[source - 1].lease_id.load());
      ownership.revoked.store(true);
    }
  }
  transaction.generation.fetch_add(1);  // Odd: a new snapshot is being written.
  if (transaction.xid.load() != message.xid || message.type != 3) {
    transaction.candidate_xid.store(0);
    transaction.candidate_address.store(0);
  }
  transaction.xid.store(message.xid);
  transaction.request_type.store(message.type);
  transaction.mac_low.store(read_address(message.mac));
  transaction.mac_high.store(uint32_t(message.mac[4]) | (uint32_t(message.mac[5]) << 8));
  transaction.seen.store(now_ms());
  transaction.generation.fetch_add(1);  // Even: all fields belong to this request.
  this->driver_tx_busy_.store(false);
  return true;
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
uint8_t MeshIpNetif::dhcp_destination_(const DhcpMessage &message, uint32_t *peer_epoch) {
  if (!this->gateway_active_())
    return 0;
  const uint32_t source = lwip_ntohl(message.source);
  if ((source & this->mask_.load()) != (this->address_.load() & this->mask_.load()))
    return 0;  // This lab has no external DHCP relay or off-subnet server.
  const uint32_t mac_low = read_address(message.mac);
  const uint32_t mac_high = uint32_t(message.mac[4]) | (uint32_t(message.mac[5]) << 8);
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    const uint32_t epoch = this->identity_requests_[i].epoch.load();
    if (!this->peer_epoch_current_(i + 1, epoch))
      continue;
    DhcpTransaction &transaction = this->dhcp_transactions_[i];
    const uint32_t generation = transaction.generation.load();
    if (generation == 0 || (generation & 1) != 0)
      continue;
    const uint32_t xid = transaction.xid.load(), seen = transaction.seen.load();
    const uint32_t low = transaction.mac_low.load(), high = transaction.mac_high.load();
    if (transaction.generation.load() == generation && xid == message.xid && low == mac_low && high == mac_high &&
        uint32_t(now_ms() - seen) < DHCP_TRANSACTION_MS) {
      if (peer_epoch != nullptr)
        *peer_epoch = epoch;
      if (message.type == 5 && transaction.request_type.load() == 3) {
        // Client proof requests must refer to a real server ACK observed here,
        // never merely an offered address or a mesh client's chosen address.
        const uint32_t candidate = message.offered_address != 0 ? message.offered_address : message.client_address;
        DhcpOwnership &ownership = this->dhcp_ownership_[i];
        if (((ownership.revoked.load() || this->gateway_candidates_ != 0) &&
             (ownership.revoked_xid.load() == message.xid || ownership.revoked_lease_xid.load() == message.xid)) ||
            message.lifetime_seconds < 4)
          return i + 1;
        if (ownership.generation.load() == 0 || ownership.xid.load() != message.xid) {
          RemoteWitness &remote = this->remote_witnesses_[i];
          if (remote.address.load() != lwip_ntohl(candidate))
            remote.active.store(false);
          ownership.generation.fetch_add(1);
          ownership.address.store(lwip_ntohl(candidate));
          ownership.xid.store(message.xid);
          ownership.seconds.store(message.lifetime_seconds);
          // SDK uptime is monotonic 64-bit; floor to seconds at ACK reception.
          // Never mistake a concurrent reconstructed-clock update for expiry.
          ownership.started.store(now_seconds());
          ownership.local.store(true);
          ownership.generation.fetch_add(1);
          ownership.revoked.store(false);
          ownership.active.store(true);
          if (this->gateway_candidates_ != 0 && this->peers_[i].ip.load() != lwip_ntohl(candidate)) {
            // Same-IP renewal changes evidence, not the established grant.
            // A different address invalidates old proxy ownership immediately.
            this->peers_[i].fallback.store(false);
            this->peers_[i].endpoint.store(false);
          }
          this->schedule_();
        } else if (ownership.address.load() == lwip_ntohl(candidate)) {
          // An imported witness may precede our own copy of the same ACK.
          // Mark real local observation without moving its existing deadline.
          ownership.local.store(true);
        } else {
          return i + 1;  // Same transaction cannot silently change its address.
        }
        transaction.candidate_address.store(lwip_ntohl(candidate));
        transaction.candidate_xid.store(message.xid);
      } else if (message.type == 6) {
        this->dhcp_ownership_[i].revoked_xid.store(message.xid);
        this->dhcp_ownership_[i].revoked_lease_xid.store(this->peers_[i].lease_id.load());
        this->dhcp_ownership_[i].revoked.store(true);
        this->dhcp_ownership_[i].active.store(false);
        this->peers_[i].fallback.store(false);
        this->peers_[i].endpoint.store(false);
        this->remote_witnesses_[i].active.store(false);
        transaction.candidate_xid.store(0);
        transaction.candidate_address.store(0);
      }
      return i + 1;
    }
  }
  return 0;
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::capture_dhcp_reply_(struct pbuf *packet, uint16_t length) {
  const uint32_t generation = this->gateway_generation_.load();
  if (!this->gateway_active_() || length > MAX_PACKET_SIZE || length < 268)
    return false;
  if (this->driver_tx_busy_.exchange(true)) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  // Observe the ACK/NAK independently of TX admission, including when every
  // queue slot is occupied. Parse the pbuf in place instead of retaining a
  // second complete packet solely for DHCP inspection.
  const PbufPacketView view{packet, 14, length};
  const PacketReader reader{&view, read_pbuf_packet};
  DhcpMessage message;
  uint8_t destination = 0;
  uint32_t peer_epoch = 0;
  if (parse_dhcp_reply(reader, length, message))
    destination = this->dhcp_destination_(message, &peer_epoch);
  if (destination != 0) {
    IpFlowQueue::Key key;
    key.source = lwip_ntohl(message.source);
    key.target = lwip_ntohl(message.destination);
    key.source_port = 67;
    key.target_port = 68;
    key.protocol = 17;
    key.destination = destination;
    IpFlowQueue::Reservation reservation;
    IpPacket *outgoing = this->reserve_outgoing_(key, reservation);
    bool queued = false;
    if (outgoing != nullptr) {
      outgoing->generation = generation;
      outgoing->destination = destination;
      outgoing->peer_epoch = peer_epoch;
      outgoing->ingress_source = 0;
      outgoing->ingress_epoch = 0;
      outgoing->gateway_ingress = false;
      outgoing->length = length;
      const bool copied = pbuf_copy_partial(packet, outgoing->data, length, 14) == length;
      queued = this->commit_outgoing_(reservation, copied);
    }
    if (queued)
      this->mesh_tx_.fetch_add(1);
    else
      this->queue_drops_.fetch_add(1);
  }
  this->driver_tx_busy_.store(false);
  return destination != 0;
}
#endif

bool MeshIpNetif::set_peer(uint8_t node_id, uint32_t ip, bool fallback) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) ip;
  (void) fallback;
  return false;
#else
  if (this->gateway_candidates_ != 0) {
    // Legacy status packets carry no challenge or lease identity. They may
    // withdraw a route but never establish/refresh endpoint authorization.
    if (node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || fallback)
      return false;
    return this->withdraw_endpoint(node_id);
  }
  if (!this->gateway_active_() || !this->valid_peer_address_(node_id, ip) ||
      (fallback && !this->gateway_lease_valid_(node_id, ip))) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  Peer &peer = this->peers_[node_id - 1];
  peer.ip.store(ip);
  peer.seen.store(now_ms());
  peer.fallback.store(fallback);
  this->schedule_();
  return true;
#endif
}

bool MeshIpNetif::local_lease_witness(uint8_t node_id, uint32_t &address, uint32_t &xid,
                                      uint32_t &remaining_seconds) const {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) xid;
  (void) remaining_seconds;
  return false;
#else
  if (!this->configured_.load() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0)
    return false;
  const DhcpOwnership &ownership = this->dhcp_ownership_[node_id - 1];
  const uint32_t generation = ownership.generation.load();
  const uint32_t ip = ownership.address.load(), transaction = ownership.xid.load();
  uint32_t remaining;
  if (generation == 0 || (generation & 1) != 0 || !ownership.local.load() || !this->valid_peer_address_(node_id, ip) ||
      !this->witness_remaining_(node_id, ip, transaction, remaining))
    return false;
  // Uptime-second fractions differ between devices. Deduct one conservative
  // second rather than exporting an expiry later than this observation.
  if (remaining != UINT32_MAX) {
    if (remaining <= 1)
      return false;
    remaining--;
  }
  if (ownership.generation.load() != generation || !ownership.local.load() || !ownership.active.load() ||
      ownership.revoked.load())
    return false;
  address = ip;
  xid = transaction;
  remaining_seconds = remaining;
  return true;
#endif
}

bool MeshIpNetif::install_peer_witness(uint8_t node_id, uint32_t address, uint32_t xid, uint32_t remaining_seconds) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) xid;
  (void) remaining_seconds;
  return false;
#else
  if (!this->configured_.load() || this->gateway_candidates_ == 0 || !this->candidate_(this->node_id_) ||
      node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || xid == 0 ||
      remaining_seconds == 0 || (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0 ||
      !this->valid_peer_address_(node_id, address) || this->driver_tx_busy_.exchange(true))
    return false;
  const DhcpOwnership &local = this->dhcp_ownership_[node_id - 1];
  const Peer &peer = this->peers_[node_id - 1];
  RemoteWitness &remote = this->remote_witnesses_[node_id - 1];
  const bool same = remote.generation.load() != 0 && remote.address.load() == address && remote.xid.load() == xid;
  const uint32_t now = now_seconds();
  const uint32_t lifetime = remote.seconds.load(), elapsed = uint32_t(now - remote.started.load());
  if ((peer.identity_known.load() && (peer.desired_address.load() != address || peer.desired_xid.load() != xid)) ||
      (local.revoked_xid.load() == xid || local.revoked_lease_xid.load() == xid) ||
      (same && (!remote.active.load() || (lifetime != UINT32_MAX && elapsed >= lifetime)))) {
    this->driver_tx_busy_.store(false);
    return false;
  }
  if (same) {
    if (remaining_seconds != UINT32_MAX && (lifetime == UINT32_MAX || remaining_seconds < lifetime - elapsed)) {
      remote.generation.fetch_add(1);
      remote.started.store(now);
      remote.seconds.store(remaining_seconds);
      remote.generation.fetch_add(1);
    }
  } else {
    remote.generation.fetch_add(1);
    remote.active.store(false);
    remote.address.store(address);
    remote.xid.store(xid);
    remote.seconds.store(remaining_seconds);
    remote.started.store(now);
    remote.generation.fetch_add(1);
    remote.active.store(true);
  }
  // Importing competing gateway evidence never edits local ACK evidence or an
  // established endpoint grant. Only a fresh client challenge selects a token.
  this->driver_tx_busy_.store(false);
  this->schedule_();
  return true;
#endif
}

bool MeshIpNetif::authorize_endpoint(uint8_t node_id, uint32_t address, uint32_t lease_id, uint32_t remaining_seconds,
                                     uint32_t fresh_budget_ms) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) lease_id;
  (void) remaining_seconds;
  (void) fresh_budget_ms;
  return false;
#else
  if (!this->configured_.load() || this->gateway_candidates_ == 0 || !this->gateway_active_() || node_id == 0 ||
      node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || lease_id == 0 || remaining_seconds == 0 ||
      fresh_budget_ms == 0 || fresh_budget_ms > PEER_LEASE_MS ||
      (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0 || !this->valid_peer_address_(node_id, address) ||
      this->driver_tx_busy_.exchange(true))
    return false;
  Peer &peer = this->peers_[node_id - 1];
  peer.desired_address.store(address);
  peer.desired_xid.store(lease_id);
  peer.identity_known.store(true);
  // A freshly proved address change retires occupancy of the old IP as well
  // as its forwarding grant. Keep ACK evidence fields for stale-token fencing,
  // but do not block the router's legitimate reassignment to another node.
  DhcpOwnership &local = this->dhcp_ownership_[node_id - 1];
  RemoteWitness &remote = this->remote_witnesses_[node_id - 1];
  if (local.address.load() != address)
    local.active.store(false);
  if (remote.address.load() != address)
    remote.active.store(false);
  if (peer.ip.load() != address) {
    // A fresh client proof for another address immediately retires the old IP,
    // even if the new witness has not reached this gateway yet.
    peer.fallback.store(false);
    peer.endpoint.store(false);
  }
  uint32_t witness_remaining;
  if (!this->witness_remaining_(node_id, address, lease_id, witness_remaining)) {
    this->driver_tx_busy_.store(false);
    this->schedule_();
    return false;
  }
  const uint32_t now = now_seconds();
  uint32_t lifetime = std::min(remaining_seconds, witness_remaining);
  if (peer.generation.load() != 0 && peer.ip.load() == address && peer.lease_id.load() == lease_id) {
    const uint32_t old_lifetime = peer.lease_seconds.load(), elapsed = uint32_t(now - peer.lease_started.load());
    // Repeated challenge replies renew reachability, never the original lease.
    if (old_lifetime != UINT32_MAX) {
      if (elapsed >= old_lifetime) {
        this->driver_tx_busy_.store(false);
        return false;
      }
      lifetime = std::min(lifetime, old_lifetime - elapsed);
    }
  }
  uint32_t budget = fresh_budget_ms;
  if (lifetime < PEER_LEASE_MS / 1000)
    budget = std::min(budget, lifetime * 1000);
  peer.generation.fetch_add(1);
  peer.fallback.store(false);
  peer.endpoint.store(true);
  peer.lease_id.store(lease_id);
  peer.ip.store(address);
  peer.lease_seconds.store(lifetime);
  peer.lease_started.store(now);
  peer.seen.store(now_ms() - (PEER_LEASE_MS - budget));
  peer.generation.fetch_add(1);
  peer.fallback.store(true);
  this->driver_tx_busy_.store(false);
  this->schedule_();
  return true;
#endif
}

bool MeshIpNetif::has_lease_witness(uint8_t node_id, uint32_t address, uint32_t xid) const {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) xid;
  return false;
#else
  if (!this->configured_.load() || this->gateway_candidates_ == 0 || !this->gateway_active_() || node_id == 0 ||
      node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0 || !this->valid_peer_address_(node_id, address))
    return false;
  uint32_t remaining;
  return this->witness_remaining_(node_id, address, xid, remaining);
#endif
}

bool MeshIpNetif::withdraw_endpoint(uint8_t node_id) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  return false;
#else
  if (!this->configured_.load() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      !this->peer_current_(node_id) || (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0 ||
      this->driver_tx_busy_.exchange(true))
    return false;
  this->peers_[node_id - 1].fallback.store(false);
  this->peers_[node_id - 1].endpoint.store(false);
  this->driver_tx_busy_.store(false);
  this->schedule_();
  return true;
#endif
}

bool MeshIpNetif::revoke_peer(uint8_t node_id, uint32_t address, uint32_t lease_xid) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  (void) address;
  (void) lease_xid;
  return false;
#else
  if (!this->configured_.load() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      !this->peer_current_(node_id) || (this->dhcp_peer_mac_mask_ & (1U << (node_id - 1))) == 0 ||
      !unicast_address_(address))
    return false;
  if (this->driver_tx_busy_.exchange(true))
    return false;
  Peer &peer = this->peers_[node_id - 1];
  DhcpOwnership &ownership = this->dhcp_ownership_[node_id - 1];
  const uint32_t cached = ownership.address.load() != 0 ? ownership.address.load() : peer.ip.load();
  if ((cached != 0 && cached != address) || (ownership.generation.load() != 0 && ownership.xid.load() != lease_xid)) {
    this->driver_tx_busy_.store(false);
    return false;
  }
  // Keep the address as a tombstone, so duplicate releases remain idempotent
  // and late heartbeats cannot turn the old lease back into live proxying.
  ownership.managed.store(true);
  ownership.revoked_xid.store(this->dhcp_transactions_[node_id - 1].xid.load());
  ownership.revoked_lease_xid.store(lease_xid);
  ownership.revoked.store(true);
  ownership.active.store(false);
  peer.fallback.store(false);
  peer.endpoint.store(false);
  this->remote_witnesses_[node_id - 1].active.store(false);
  this->lease_probes_[node_id - 1].phase.store(0);
  this->dhcp_transactions_[node_id - 1].candidate_xid.store(0);
  this->dhcp_transactions_[node_id - 1].candidate_address.store(0);
  this->driver_tx_busy_.store(false);
  this->schedule_();
  return true;
#endif
}

uint32_t MeshIpNetif::peer_mesh_address(uint8_t node_id) const {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node_id;
  return 0;
#else
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || !this->gateway_active_() ||
      !this->station_connected_.load() || !this->available_.load())
    return 0;
  const auto &peer = this->peers_[node_id - 1];
  const uint32_t address = peer.ip.load();
  // Load the worker's timestamp BEFORE sampling time. A newly published stamp
  // must not underflow against an earlier captured clock and appear expired.
  const uint32_t seen = peer.seen.load();
  const uint32_t now = now_ms();
  if (!peer.fallback.load() || uint32_t(now - seen) >= PEER_LEASE_MS ||
      (this->gateway_candidates_ == 0 ? !this->gateway_lease_valid_(node_id, address)
                                      : !this->endpoint_lease_valid_(node_id, address)))
    return 0;
  return this->peer_for_ip_(address, true) == node_id ? address : 0;
#endif
}

bool MeshIpNetif::has_active_mesh_clients() const {
#ifndef MESH_IP_CLIENT_ONLY
  if (!this->gateway_active_())
    return false;
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    if (this->peer_mesh_address(node) != 0)
      return true;
#ifdef MESH_IPV6
    if (this->ipv6_peer_active_(node))
      return true;
#endif
  }
#endif
  return false;
}

bool MeshIpNetif::unicast_address_(uint32_t address) {
  const uint32_t host = lwip_ntohl(address);
  return host != 0 && host != 0xffffffffU && (host >> 24) != 0 && (host >> 24) != 127 && (host >> 28) < 14;
}

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::valid_peer_address_(uint8_t node_id, uint32_t ip) const {
  const uint32_t own = this->address_.load();
  const uint32_t mask = this->mask_.load();
  const uint32_t host_mask = ~lwip_ntohl(mask);
  const uint32_t host_part = lwip_ntohl(ip) & host_mask;
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || !unicast_address_(ip) ||
      own == 0 || !this->peer_current_(node_id) || mask == 0 || host_mask == 0 || (host_mask & (host_mask + 1)) != 0 ||
      (ip & mask) != (own & mask) || host_part == 0 || host_part == host_mask || ip == own ||
      ip == this->gateway_.load())
    return false;
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    if (i + 1 == node_id)
      continue;
    if (this->gateway_candidates_ == 0) {
      if (this->peers_[i].ip.load() == ip && this->gateway_lease_valid_(i + 1, ip))
        return false;
    } else {
      uint32_t remaining;
      if ((this->peers_[i].ip.load() == ip && this->endpoint_lease_valid_(i + 1, ip)) ||
          (this->dhcp_ownership_[i].address.load() == ip && this->gateway_lease_valid_(i + 1, ip)) ||
          (this->remote_witnesses_[i].address.load() == ip &&
           this->witness_remaining_(i + 1, ip, this->remote_witnesses_[i].xid.load(), remaining)))
        return false;
    }
  }
  return true;
}
#endif

void MeshIpNetif::set_transport_wake(void *context, void (*wake)(void *)) {
  portENTER_CRITICAL(&this->tx_lock_);
  this->transport_wake_context_ = context;
  this->transport_wake_ = wake;
  portEXIT_CRITICAL(&this->tx_lock_);
}

bool MeshIpNetif::consume_outgoing(uint8_t *target, size_t capacity, QueuedIpMetadata &metadata) {
  metadata = {};
  if (target == nullptr || capacity < MAX_PACKET_SIZE)
    return false;
  if (!this->configured_.load() || !this->transport_current_() || (!this->role_current_() && !this->gateway_active_()))
    return false;
  while (true) {
    portENTER_CRITICAL(&this->tx_lock_);
    const bool popped = this->tx_flows_.consume(target, capacity, metadata);
    portEXIT_CRITICAL(&this->tx_lock_);
    if (!popped) {
      metadata = {};
      return false;
    }
    if (metadata.generation == this->gateway_generation_.load() &&
        this->peer_epoch_current_(metadata.destination, metadata.peer_epoch) &&
        (metadata.ingress_source == 0 || this->peer_epoch_current_(metadata.ingress_source, metadata.ingress_epoch)))
      return true;
  }
}

bool MeshIpNetif::pop_outgoing(IpPacket &packet) {
  QueuedIpMetadata metadata;
  if (!this->consume_outgoing(packet.data, sizeof(packet.data), metadata))
    return false;
  packet.generation = metadata.generation;
  packet.peer_epoch = metadata.peer_epoch;
  packet.ingress_epoch = metadata.ingress_epoch;
  packet.destination = metadata.destination;
  packet.ingress_source = metadata.ingress_source;
  packet.gateway_ingress = metadata.gateway_ingress;
  packet.length = metadata.length;
  return true;
}

bool MeshIpNetif::valid_ipv4_(const uint8_t *packet, size_t length) {
  if (packet == nullptr || length < 20 || length > MAX_PACKET_SIZE || (packet[0] >> 4) != 4)
    return false;
  const size_t header_length = (packet[0] & 15) * 4;
  if (header_length < 20 || header_length > length || read_be16(packet + 2) != length)
    return false;
  uint32_t checksum = 0;
  for (size_t i = 0; i < header_length; i += 2)
    checksum += read_be16(packet + i);
  checksum = (checksum & 0xffffU) + (checksum >> 16);
  checksum = (checksum & 0xffffU) + (checksum >> 16);
  return checksum == 0xffffU;
}

bool MeshIpNetif::deliver_mesh(uint8_t source, const uint8_t *packet, size_t length) {
#ifdef MESH_IPV6
  if (packet != nullptr && length >= 40 && (packet[0] >> 4) == 6)
    return this->deliver_ipv6_(source, packet, length);
#endif
  return this->deliver_ipv4_(source, packet, length);
}

bool MeshIpNetif::deliver_ipv4_(uint8_t source, const uint8_t *packet, size_t length) {
  const uint32_t generation = this->gateway_generation_.load();
  const uint32_t peer_epoch =
      source != 0 && source <= mesh_limits::MAX_NODES ? this->identity_requests_[source - 1].epoch.load() : 0;
  if (!this->configured_.load() || !this->transport_current_() ||
      (!this->role_current_() && !this->gateway_active_()) || source == 0 || source > mesh_limits::MAX_NODES ||
      source == this->node_id_ || !this->peer_epoch_current_(source, peer_epoch) || !valid_ipv4_(packet, length)) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  const uint32_t source_ip = read_address(packet + 12);
  const uint32_t destination_ip = read_address(packet + 16);
  const uint32_t mask = this->mask_.load();
#ifdef MESH_IP_CLIENT_ONLY
  const bool bootstrap = false;
#else
  const bool bootstrap = this->gateway_active_() && this->valid_dhcp_request_(source, packet, length);
  const size_t header_length = (packet[0] & 15) * 4;
  const bool dhcp_port_pair = packet[9] == 17 && length >= header_length + 8 &&
                              read_be16(packet + header_length) == 68 && read_be16(packet + header_length + 2) == 67;
  if (this->gateway_active_() && dhcp_port_pair && !bootstrap) {
    // Malformed/spoofed unicast renewals must not bypass DHCP validation by
    // falling through to ordinary traffic with a previously advertised IP.
    this->invalid_packets_.fetch_add(1);
    return false;
  }
#endif
  bool gateway_ingress = bootstrap;
#ifndef MESH_IP_CLIENT_ONLY
  gateway_ingress |= this->gateway_source_valid_(source, source_ip);
#endif
  if (!bootstrap) {
    // No cached address or advertisement is required for validated DHCP. All
    // other zero-source/broadcast traffic remains excluded from this tunnel.
    if (!unicast_address_(source_ip) || !unicast_address_(destination_ip) ||
        (mask != 0 && (destination_ip & mask) == (this->address_.load() & mask) &&
         ((destination_ip | mask) == 0xffffffffU || (destination_ip & ~mask) == 0))) {
      this->invalid_packets_.fetch_add(1);
      return false;
    }
    // The encrypted mesh authenticates the node ID. Bind that ID to its
    // advertised source IP; accept gateway traffic only for this client's IP.
    const bool from_gateway = this->gateway_candidates_ != 0 ? this->candidate_(source) : source == this->gateway_id_;
    if (!gateway_ingress && (!from_gateway || destination_ip != this->address_.load() ||
                             (!this->station_connected_.load() && !this->mesh_path_validated_.load()))) {
      this->invalid_packets_.fetch_add(1);
      return false;
    }
  }
  IpPacket incoming;
  incoming.generation = generation;
  incoming.gateway_ingress = gateway_ingress;
  incoming.destination = source;
  incoming.peer_epoch = peer_epoch;
  incoming.length = length;
  std::memcpy(incoming.data, packet, length);
  if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  this->schedule_();
  return true;
}

MeshIpNetif::IpPacket *MeshIpNetif::reserve_outgoing_(const IpFlowQueue::Key &key,
                                                      IpFlowQueue::Reservation &reservation) {
  // Only queue metadata is locked. Each admitted writer owns its unpublished
  // slot, so full pbuf/memcpy payload copies do not stall the other producers.
  portENTER_CRITICAL(&this->tx_lock_);
  const auto admitted = this->tx_flows_.reserve(key, reservation);
  IpPacket *packet =
      admitted == IpFlowQueue::Admission::ACCEPTED ? this->tx_flows_.reserved_packet(reservation) : nullptr;
  portEXIT_CRITICAL(&this->tx_lock_);
  if (admitted == IpFlowQueue::Admission::FLOW_LIMIT)
    this->flow_backpressure_.fetch_add(1);
  return packet;
}

bool MeshIpNetif::commit_outgoing_(const IpFlowQueue::Reservation &reservation, bool publish) {
  portENTER_CRITICAL(&this->tx_lock_);
  const IpPacket *packet = this->tx_flows_.reserved_packet(reservation);
  const bool current =
      publish && packet != nullptr && packet->generation == this->gateway_generation_.load() &&
      this->transport_current_() && (this->role_current_() || this->gateway_active_()) &&
      this->peer_epoch_current_(packet->destination, packet->peer_epoch) &&
      (packet->ingress_source == 0 || this->peer_epoch_current_(packet->ingress_source, packet->ingress_epoch));
  const bool committed = current && this->tx_flows_.commit(reservation);
  if (!committed)
    this->tx_flows_.cancel(reservation);
  const auto wake = committed ? this->transport_wake_ : nullptr;
  void *const wake_context = this->transport_wake_context_;
  portEXIT_CRITICAL(&this->tx_lock_);
  // Publish the complete packet before waking its consumer. The notification
  // must never run inside the queue's metadata critical section.
  if (wake != nullptr)
    wake(wake_context);
  return committed;
}

bool MeshIpNetif::enqueue_(uint8_t destination, const uint8_t *packet, size_t length, bool count_rejection,
                           uint8_t ingress_source, uint32_t ingress_epoch) {
  const uint32_t generation = this->gateway_generation_.load();
  const uint32_t peer_epoch = destination != 0 && destination <= mesh_limits::MAX_NODES
                                  ? this->identity_requests_[destination - 1].epoch.load()
                                  : 0;
  if (!this->transport_current_() || (!this->role_current_() && !this->gateway_active_()) ||
      !this->peer_epoch_current_(destination, peer_epoch) ||
      (ingress_source != 0 && !this->peer_epoch_current_(ingress_source, ingress_epoch)) ||
      (!valid_ipv4_(packet, length)
#ifdef MESH_IPV6
       && !([&]() {
            Ipv6PacketInfo info;
            return inspect_ipv6(packet, length, info);
          })()
#endif
           )) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  IpFlowQueue::Reservation reservation;
  IpPacket *outgoing = this->reserve_outgoing_(IpFlowQueue::classify(destination, packet, length), reservation);
  if (outgoing == nullptr) {
    if (count_rejection)
      this->queue_drops_.fetch_add(1);
    return false;
  }
  outgoing->generation = generation;
  outgoing->destination = destination;
  outgoing->peer_epoch = peer_epoch;
  outgoing->ingress_source = ingress_source;
  outgoing->ingress_epoch = ingress_epoch;
  outgoing->gateway_ingress = false;
  outgoing->length = length;
  std::memcpy(outgoing->data, packet, length);
  if (!this->commit_outgoing_(reservation)) {
    if (count_rejection)
      this->queue_drops_.fetch_add(1);
    return false;
  }
  this->mesh_tx_.fetch_add(1);
  return true;
}

bool MeshIpNetif::enqueue_(uint8_t destination, struct pbuf *packet, uint16_t offset, uint16_t length,
                           bool from_driver) {
  const uint32_t generation = this->gateway_generation_.load();
  const uint32_t peer_epoch = destination != 0 && destination <= mesh_limits::MAX_NODES
                                  ? this->identity_requests_[destination - 1].epoch.load()
                                  : 0;
  if (!this->transport_current_() || (!this->role_current_() && !this->gateway_active_()) ||
      !this->peer_epoch_current_(destination, peer_epoch) || packet == nullptr || offset > packet->tot_len ||
      length > packet->tot_len - offset || length > MAX_PACKET_SIZE || length < 20) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
#ifdef MESH_IP_CLIENT_ONLY
  if (from_driver)
    return false;
#else
  if (from_driver && this->driver_tx_busy_.exchange(true)) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
#endif
  uint8_t header[64];
  const uint16_t header_bytes = std::min<size_t>(sizeof(header), length);
  bool queued = false;
  if (pbuf_copy_partial(packet, header, header_bytes, offset) != header_bytes || !valid_ipv4_(header, length)
#ifndef MESH_IP_CLIENT_ONLY
      || (from_driver && this->peer_for_ip_(read_address(header + 16), false) != destination)
#endif
  ) {
    this->invalid_packets_.fetch_add(1);
  } else {
    IpFlowQueue::Reservation reservation;
    IpPacket *outgoing = this->reserve_outgoing_(IpFlowQueue::classify(destination, header, header_bytes), reservation);
    if (outgoing != nullptr) {
      outgoing->generation = generation;
      outgoing->destination = destination;
      outgoing->peer_epoch = peer_epoch;
      outgoing->ingress_source = 0;
      outgoing->ingress_epoch = 0;
      outgoing->gateway_ingress = false;
      outgoing->length = length;
      const bool copied = pbuf_copy_partial(packet, outgoing->data, length, offset) == length;
      queued = this->commit_outgoing_(reservation, copied);
    }
    if (queued)
      this->mesh_tx_.fetch_add(1);
    else
      this->queue_drops_.fetch_add(1);
  }
#ifndef MESH_IP_CLIENT_ONLY
  if (from_driver)
    this->driver_tx_busy_.store(false);
#endif
  return queued;
}

#ifndef MESH_IP_CLIENT_ONLY
uint8_t MeshIpNetif::peer_for_ip_(uint32_t ip, bool require_fallback) const {
  if (!this->gateway_active_() || !unicast_address_(ip))
    return 0;
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    const Peer &peer = this->peers_[i];
    const uint32_t seen = peer.seen.load();
    const uint32_t now = now_ms();
    if (peer.ip.load() == ip && uint32_t(now - seen) < PEER_LEASE_MS && this->gateway_source_valid_(i + 1, ip) &&
        (!require_fallback || peer.fallback.load()))
      return i + 1;
  }
  return 0;
}
#endif

err_t MeshIpNetif::netif_init_(struct netif *netif) {
  netif->name[0] = 'm';
  netif->name[1] = 's';
  netif->mtu = 1280;
  netif->flags = 0;  // Raw IP, without Ethernet/ARP or broadcast handling.
  netif->output = netif_output_;
#ifdef MESH_IPV6
  netif->output_ip6 = netif_output_ipv6_;
  netif->flags |= NETIF_FLAG_MLD6;
#endif
  return ERR_OK;
}

err_t MeshIpNetif::netif_output_(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination) {
  auto *self = instance_;
  if (self == nullptr || netif != &self->virtual_netif_ || !self->available_.load())
    return ERR_RTE;
  // IDF's source-address route hook can choose this /32 alias ahead of STA even
  // while STA is connected. Preserve direct Wi-Fi for such packets rather than
  // accidentally tunnelling normal traffic (or dropping gateway responses).
  struct netif *station = self->station_netif_;
  if (station != nullptr && self->station_connected_.load() && netif_is_up(station) && netif_is_link_up(station) &&
      netif_ip4_addr(station)->addr == self->address_.load() && station->output != nullptr)
    return station->output(station, packet, destination);
  if (!self->role_current_() || !self->mesh_path_validated_.load() || self->node_id_ == self->gateway_id_)
    return ERR_RTE;
  return self->enqueue_(self->gateway_id_, packet, 0, packet->tot_len) ? ERR_OK : ERR_MEM;
}

#ifndef MESH_IP_CLIENT_ONLY
err_t MeshIpNetif::station_output_(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination) {
  auto *self = instance_;
  if (self == nullptr || self->station_netif_ != netif || self->original_station_output_ == nullptr)
    return ERR_IF;
  const uint8_t peer = self->peer_for_ip_(destination->addr, true);
  if (peer != 0)
    return self->enqueue_(peer, packet, 0, packet->tot_len) ? ERR_OK : ERR_MEM;
  return self->original_station_output_(netif, packet, destination);
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
err_t MeshIpNetif::station_input_(struct pbuf *packet, struct netif *netif) {
#ifdef MESH_HAS_ETHERNET
  // Use lwIP's normal input mailbox and retain the pbuf, with no packet copy.
  // Queued input and interface changes then have the same TCP/IP owner.
  return tcpip_inpkt(packet, netif, lan_input_);
}

err_t MeshIpNetif::lan_input_(struct pbuf *packet, struct netif *netif) {
#endif
  auto *self = instance_;
#ifdef MESH_HAS_ETHERNET
  if (self == nullptr || self->station_netif_ != netif || !self->transport_current_())
    return ethernet_input(packet, netif);
#else
  if (self == nullptr || self->station_netif_ != netif || self->original_station_input_ == nullptr)
    return ERR_IF;
#endif
#ifdef MESH_IPV6
  bool consume_ipv6 = false;
  self->station_input_ipv6_(packet, consume_ipv6);
  if (consume_ipv6) {
    pbuf_free(packet);
    return ERR_OK;
  }
#endif
  if (!self->gateway_active_())
#ifdef MESH_HAS_ETHERNET
    return ethernet_input(packet, netif);
#else
    return self->original_station_input_(packet, netif);
#endif
  uint8_t header[42];
  const uint16_t copied = pbuf_copy_partial(packet, header, sizeof(header), 0);
  if (copied >= 34 && read_be16(header + 12) == 0x0800) {
    const uint16_t length = read_be16(header + 16);
    const uint16_t header_length = (header[14] & 15) * 4;
    uint8_t ports[4];
    const bool dhcp = header[23] == 17 && header_length >= 20 &&
                      pbuf_copy_partial(packet, ports, sizeof(ports), 14 + header_length) == sizeof(ports) &&
                      read_be16(ports) == 67 && read_be16(ports + 2) == 68;
    if (dhcp && length <= packet->tot_len - 14 && self->capture_dhcp_reply_(packet, length)) {
      pbuf_free(packet);
      return ERR_OK;
    }
    const uint8_t destination = self->peer_for_ip_(read_address(header + 30), false);
    if (destination != 0) {
      if (length <= packet->tot_len - 14)
        self->enqueue_(destination, packet, 14, length, true);
      else
        self->invalid_packets_.fetch_add(1);
      pbuf_free(packet);
      return ERR_OK;
    }
  } else if (copied == sizeof(header) && read_be16(header + 12) == 0x0806 && read_be16(header + 14) == 1 &&
             read_be16(header + 16) == 0x0800 && header[18] == 6 && header[19] == 4 &&
             (read_be16(header + 20) == 1 || read_be16(header + 20) == 2)) {
    self->observe_probe_arp_(header);
    if (read_be16(header + 20) != 1)
#ifdef MESH_HAS_ETHERNET
      return ethernet_input(packet, netif);
#else
      return self->original_station_input_(packet, netif);
#endif
    const uint32_t claimed = read_address(header + 38);
    const uint32_t requester = read_address(header + 28);
    const uint8_t peer = self->peer_for_ip_(claimed, true);
    if (requester != 0 && requester != claimed && self->station_connected_.load() && peer != 0) {
      ArpRequest request{};
      request.generation = self->gateway_generation_.load();
      request.peer = peer;
      request.peer_epoch = self->identity_requests_[peer - 1].epoch.load();
      request.claimed_ip = claimed;
      request.target_ip = requester;
      std::memcpy(request.target_mac, header + 22, 6);
      if (xQueueSend(self->arp_queue_, &request, 0) == pdTRUE)
        self->schedule_();
      else
        self->queue_drops_.fetch_add(1);
    }
  }
#ifdef MESH_HAS_ETHERNET
  return ethernet_input(packet, netif);
#else
  return self->original_station_input_(packet, netif);
#endif
}
#endif

void MeshIpNetif::schedule_() {
  if (!this->configured_.load() || this->pending_.exchange(true))
    return;
  if (tcpip_try_callback(work_callback_, this) != ERR_OK) {
    this->pending_.store(false);
    this->queue_drops_.fetch_add(1);
  }
}

void MeshIpNetif::work_callback_(void *context) {
  auto *self = static_cast<MeshIpNetif *>(context);
  self->pending_.store(false);
  self->work_();
  const uint32_t remaining = uxTaskGetStackHighWaterMark(nullptr);
  if (remaining < self->tcpip_stack_min_.load())
    self->tcpip_stack_min_.store(remaining);
}

#ifndef MESH_IP_CLIENT_ONLY
void MeshIpNetif::arp_reply_(const ArpRequest &request) {
  if (!this->gateway_active_() || request.generation != this->gateway_generation_.load() ||
      (request.peer != 0 && !this->peer_epoch_current_(request.peer, request.peer_epoch)) ||
      this->station_netif_ == nullptr || !netif_is_up(this->station_netif_) ||
      !netif_is_link_up(this->station_netif_) || this->station_netif_->linkoutput == nullptr)
    return;
  uint8_t frame[42]{};
  std::memcpy(frame, request.target_mac, 6);
  std::memcpy(frame + 6, this->station_netif_->hwaddr, 6);
  frame[12] = 0x08;
  frame[13] = 0x06;
  frame[15] = 1;
  frame[16] = 0x08;
  frame[18] = 6;
  frame[19] = 4;
  frame[21] = 2;  // ARP reply, including unsolicited broadcast announcements.
  std::memcpy(frame + 22, this->station_netif_->hwaddr, 6);
  std::memcpy(frame + 28, &request.claimed_ip, 4);
  std::memcpy(frame + 32, request.target_mac, 6);
  std::memcpy(frame + 38, &request.target_ip, 4);
  struct pbuf *packet = pbuf_alloc(PBUF_RAW, sizeof(frame), PBUF_RAM);
  if (packet == nullptr) {
    this->queue_drops_.fetch_add(1);
    return;
  }
  pbuf_take(packet, frame, sizeof(frame));
  if (this->station_netif_->linkoutput(this->station_netif_, packet) == ERR_OK)
    this->proxy_arp_.fetch_add(1);
  pbuf_free(packet);
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
void MeshIpNetif::announce_(uint32_t address) {
  ArpRequest request{};
  request.generation = this->gateway_generation_.load();
  request.claimed_ip = request.target_ip = address;
  std::memset(request.target_mac, 0xff, 6);
  this->arp_reply_(request);
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpNetif::arp_probe_(uint32_t address) {
  if (!this->gateway_active_() || this->station_netif_ == nullptr || this->station_netif_->linkoutput == nullptr)
    return false;
  uint8_t frame[42]{};
  std::memset(frame, 0xff, 6);
  std::memcpy(frame + 6, this->station_netif_->hwaddr, 6);
  frame[12] = 0x08;
  frame[13] = 0x06;
  frame[15] = 1;
  frame[16] = 0x08;
  frame[18] = 6;
  frame[19] = 4;
  frame[21] = 1;
  std::memcpy(frame + 22, this->station_netif_->hwaddr, 6);
  std::memcpy(frame + 38, &address, 4);
  struct pbuf *packet = pbuf_alloc(PBUF_RAW, sizeof(frame), PBUF_RAM);
  if (packet == nullptr) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  pbuf_take(packet, frame, sizeof(frame));
  const bool sent = this->station_netif_->linkoutput(this->station_netif_, packet) == ERR_OK;
  if (!sent)
    this->queue_drops_.fetch_add(1);
  pbuf_free(packet);
  return sent;
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
void MeshIpNetif::observe_probe_arp_(const uint8_t *header) {
  if (!this->gateway_active_() || this->station_netif_ == nullptr ||
      std::memcmp(header + 22, this->station_netif_->hwaddr, 6) == 0)
    return;
  const uint32_t sender = read_address(header + 28), target = read_address(header + 38);
  for (LeaseProbe &probe : this->lease_probes_) {
    if (probe.phase.load() == 1 &&
        (sender == probe.address.load() || (sender == 0 && target == probe.address.load()))) {
      probe.conflict.store(true);
      this->schedule_();
    }
  }
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
void MeshIpNetif::work_probes_(bool connected) {
  const uint32_t now = now_ms();
  LeaseProbeResult request;
  while (xQueueReceive(this->probe_request_queue_, &request, 0) == pdTRUE) {
    if (!this->gateway_active_() || request.generation != this->gateway_generation_.load() ||
        !this->peer_epoch_current_(request.node_id, request.peer_epoch))
      continue;
    const DhcpTransaction &transaction = this->dhcp_transactions_[request.node_id - 1];
    if (transaction.xid.load() != request.nonce || transaction.candidate_xid.load() != request.nonce ||
        transaction.candidate_address.load() != request.address ||
        uint32_t(now - transaction.seen.load()) >= DHCP_TRANSACTION_MS ||
        !this->gateway_lease_valid_(request.node_id, request.address))
      continue;
    LeaseProbe &probe = this->lease_probes_[request.node_id - 1];
    if (probe.phase.load() != 0 && probe.address.load() == request.address && probe.nonce == request.nonce) {
      if (probe.phase.load() == 2 && uint32_t(now - probe.completed) < 10000) {
        request.conflict = probe.conflict.load();
        if (xQueueSend(this->probe_result_queue_, &request, 0) != pdTRUE)
          this->queue_drops_.fetch_add(1);
      }
      continue;
    }
    probe.phase.store(0);
    probe.address.store(request.address);
    probe.nonce = request.nonce;
    probe.generation = request.generation;
    probe.peer_epoch = request.peer_epoch;
    probe.attempts = 0;
    probe.conflict.store(false);
    for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
      if (i + 1 != request.node_id && this->lease_probes_[i].phase.load() == 1 &&
          this->lease_probes_[i].address.load() == request.address) {
        this->lease_probes_[i].conflict.store(true);
        probe.conflict.store(true);
      }
    }
    this->peers_[request.node_id - 1].fallback.store(false);
    probe.phase.store(1);
  }
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    LeaseProbe &probe = this->lease_probes_[i];
    if (probe.phase.load() == 2) {
      if (uint32_t(now - probe.completed) >= 10000)
        probe.phase.store(0);
      continue;
    }
    if (probe.phase.load() != 1 || !connected || !this->gateway_active_() ||
        probe.generation != this->gateway_generation_.load() || !this->peer_epoch_current_(i + 1, probe.peer_epoch))
      continue;
    if (uint32_t(now - this->dhcp_transactions_[i].seen.load()) >= DHCP_TRANSACTION_MS ||
        !this->gateway_lease_valid_(i + 1, probe.address.load())) {
      probe.phase.store(0);
      continue;
    }
    const bool elapsed = probe.attempts == 0 || uint32_t(now - probe.last_probe) >= 1000;
    if (probe.conflict.load() || (probe.attempts == 3 && elapsed)) {
      probe.completed = now;
      probe.phase.store(2);
      LeaseProbeResult result;
      result.node_id = i + 1;
      result.address = probe.address.load();
      result.nonce = probe.nonce;
      result.conflict = probe.conflict.load();
      result.generation = probe.generation;
      result.peer_epoch = probe.peer_epoch;
      if (xQueueSend(this->probe_result_queue_, &result, 0) != pdTRUE)
        this->queue_drops_.fetch_add(1);
    } else if (elapsed) {
      probe.last_probe = now;
      if (this->arp_probe_(probe.address.load()))
        probe.attempts++;
    }
  }
}
#endif

#ifdef MESH_HAS_ETHERNET
bool MeshIpNetif::apply_native_uplink_() {
  const uint32_t revision = this->native_uplink_revision_.load();
  if ((revision & 1U) != 0)
    return false;
  const auto requested = this->native_uplink_.load();
  auto *handle = esp_netif_get_handle_from_ifkey(native_uplink_key(requested));
  auto *selected = handle == nullptr ? nullptr : static_cast<struct netif *>(esp_netif_get_netif_impl(handle));
  if (revision != this->native_uplink_revision_.load())
    return false;
  if (revision == this->applied_native_uplink_revision_.load() && selected == this->station_netif_)
    return true;
#ifndef MESH_IP_CLIENT_ONLY
  if (this->driver_tx_busy_.exchange(true))
    return false;
  // Retire LAN-bound ownership before changing the interface, retaining each
  // member's authenticated identity and the mesh transport/routing state.
  for (size_t i = 0; i < mesh_limits::MAX_NODES; ++i)
    this->reset_peer_identity_state_(i);
  if (this->station_netif_ != nullptr) {
    if (this->station_netif_->input == station_input_)
      this->station_netif_->input = this->original_station_input_;
    if (this->station_netif_->output == station_output_)
      this->station_netif_->output = this->original_station_output_;
  }
  this->original_station_input_ = nullptr;
  this->original_station_output_ = nullptr;
  xQueueReset(this->arp_queue_);
  xQueueReset(this->probe_request_queue_);
  xQueueReset(this->probe_result_queue_);
#endif
#ifdef MESH_IPV6
#ifndef MESH_IP_CLIENT_ONLY
  if (this->station_netif_ != nullptr && this->station_netif_->output_ip6 == station_output_ipv6_)
    this->station_netif_->output_ip6 = this->original_station_output_ipv6_;
#endif
  this->original_station_output_ipv6_ = nullptr;
  this->ipv6_initialized_ = false;
  this->ipv6_previous_local_ = {};
  for (auto &prefix : this->ipv6_prefixes_) {
    prefix.revision.fetch_add(1);
    prefix.words[0].store(0);
    prefix.words[1].store(0);
    prefix.started.store(0);
    prefix.lifetime.store(0);
    prefix.revision.fetch_add(1);
  }
  this->ipv6_native_ready_.store(false);
  this->ipv6_native_link_.store(false);
  this->ipv6_path_ready_.store(false);
#endif
  portENTER_CRITICAL(&this->tx_lock_);
  this->tx_flows_.reset();
  portEXIT_CRITICAL(&this->tx_lock_);
  this->rx_pending_ = false;
  xQueueReset(this->rx_queue_);
  this->station_netif_ = selected;
  this->previous_station_connected_ = false;
  this->applied_native_uplink_.store(requested);
  this->applied_native_uplink_revision_.store(revision);
#ifndef MESH_IP_CLIENT_ONLY
  this->driver_tx_busy_.store(false);
#endif
  return revision == this->native_uplink_revision_.load();
}
#endif

void MeshIpNetif::work_() {
#ifdef MESH_HAS_ETHERNET
  if (!this->apply_native_uplink_())
    return;
#endif
  const uint32_t generation = this->gateway_generation_.load();
  if (this->applied_generation_.load() != generation && !this->apply_gateway_change_(generation))
    return;  // A later worker update retries after an in-flight driver exits.
  // A busy driver can defer one member's publication while unrelated traffic
  // and the established local endpoint continue through this service pass.
  this->apply_pending_identities_();
#ifndef MESH_HAS_ETHERNET
  if (this->station_netif_ == nullptr) {
    esp_netif_t *station = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (station != nullptr)
      this->station_netif_ = static_cast<struct netif *>(esp_netif_get_netif_impl(station));
    // A cold mesh-only node deliberately has no ESPHome STA interface yet.
    // The gateway requires one, but the raw client interface does not.
    if (this->station_netif_ == nullptr && this->node_id_ == this->gateway_id_)
      return;
  }
#endif
#ifndef MESH_IP_CLIENT_ONLY
  const bool gateway_service =
      this->gateway_enabled_.load() &&
      (this->gateway_candidates_ != 0 ? this->candidate_(this->node_id_) : this->node_id_ == this->gateway_id_);
  if (this->station_netif_ != nullptr && gateway_service) {
    // IDF STOP/START reuses this netif but netif_add/wlanif_init reset input
    // and output. Repair both hooks on the TCP/IP task after every restart,
    // preserving the current native handler and never chaining to ourselves.
    if (this->station_netif_->input != nullptr && this->station_netif_->input != station_input_) {
      this->original_station_input_ = this->station_netif_->input;
      this->station_netif_->input = station_input_;
    }
    if (this->station_netif_->output != nullptr && this->station_netif_->output != station_output_) {
      this->original_station_output_ = this->station_netif_->output;
      this->station_netif_->output = station_output_;
    }
#ifdef MESH_IPV6
    if (this->station_netif_->output_ip6 != nullptr && this->station_netif_->output_ip6 != station_output_ipv6_) {
      this->original_station_output_ipv6_ = this->station_netif_->output_ip6;
      this->station_netif_->output_ip6 = station_output_ipv6_;
    }
#endif
  } else if (this->station_netif_ != nullptr) {
    // A former gateway must leave the native STA path fully intact. Do not
    // overwrite handlers that ESP-IDF independently replaced during restart.
    if (this->station_netif_->input == station_input_ && this->original_station_input_ != nullptr)
      this->station_netif_->input = this->original_station_input_;
    if (this->station_netif_->output == station_output_ && this->original_station_output_ != nullptr)
      this->station_netif_->output = this->original_station_output_;
#ifdef MESH_IPV6
    if (this->station_netif_->output_ip6 == station_output_ipv6_ && this->original_station_output_ipv6_ != nullptr)
      this->station_netif_->output_ip6 = this->original_station_output_ipv6_;
#endif
  }
#endif
#if defined(MESH_IPV6) && defined(MESH_IP_CLIENT_ONLY)
  if (this->station_netif_ != nullptr)
    this->original_station_output_ipv6_ = this->station_netif_->output_ip6;
#endif
  const uint32_t address = this->address_.load();
  if (!this->virtual_added_) {
    ip4_addr_t ip{}, mask{}, gateway{};
    // ESP-IDF globally observes lwIP address changes and interprets netif->state
    // as esp_netif_t* when LWIP_ESP_NETIF_DATA is disabled. This raw L3 interface
    // has no esp-netif owner: keep state null, which those observers explicitly
    // recognize as unmanaged. Our singleton identifies the output interface.
    if (netif_add(&this->virtual_netif_, &ip, &mask, &gateway, nullptr, netif_init_, tcpip_input) == nullptr)
      return;
    this->virtual_added_ = true;
  }
  if (address != 0 && netif_ip4_addr(&this->virtual_netif_)->addr != address) {
    ip4_addr_t ip{address}, mask{0xffffffffU}, gateway{};
    netif_set_addr(&this->virtual_netif_, &ip, &mask, &gateway);
    netif_set_up(&this->virtual_netif_);
    netif_set_link_up(&this->virtual_netif_);
  } else if (address == 0 && netif_ip4_addr(&this->virtual_netif_)->addr != 0) {
    ip4_addr_t zero{};
#ifdef MESH_IPV6
    // IPv4 lease withdrawal must not tear down a live or bootstrapping IPv6
    // interface: netif_set_down() also discards its neighbor/router state.
    if (!this->ipv6_initialized_ || this->ipv6_station_link_()) {
#endif
      if (netif_default == &this->virtual_netif_)
        netif_set_default(this->station_netif_);
      netif_set_link_down(&this->virtual_netif_);
      netif_set_down(&this->virtual_netif_);
#ifdef MESH_IPV6
    }
#endif
    netif_set_addr(&this->virtual_netif_, &zero, &zero, &zero);
  }
  const bool connected = this->station_netif_ != nullptr && this->station_connected_.load() &&
                         netif_is_up(this->station_netif_) && netif_is_link_up(this->station_netif_) &&
                         netif_ip4_addr(this->station_netif_)->addr == address && address != 0;
  const bool reachable = connected || (this->role_current_() && this->mesh_path_validated_.load() &&
                                       this->mesh_reachable_.load() && this->node_id_ != this->gateway_id_);
  this->available_.store(address != 0 && reachable);
  this->fallback_active_.store(address != 0 && !connected && reachable);
  this->ready_.store(address != 0);
  if (connected && netif_default == &this->virtual_netif_)
    netif_set_default(this->station_netif_);
  if (address != 0 && this->node_id_ != this->gateway_id_) {
    if (!connected && reachable)
      netif_set_default(&this->virtual_netif_);
    else if (connected && netif_default == &this->virtual_netif_)
      netif_set_default(this->station_netif_);
    if (connected) {
      const uint32_t now = now_ms();
      if (!this->previous_station_connected_) {
        this->station_announcement_start_ = now;
        this->last_station_announcement_ = now;
        etharp_gratuitous(this->station_netif_);
      } else if (uint32_t(now - this->station_announcement_start_) <= 3000 &&
                 uint32_t(now - this->last_station_announcement_) >= 1000) {
        // A gateway may still have the preceding fallback heartbeat for a
        // short time. Repeat after it stops proxying so direct MAC ownership
        // wins even when its final announcement raced our initial one.
        this->last_station_announcement_ = now;
        etharp_gratuitous(this->station_netif_);
      }
    }
  }
  this->previous_station_connected_ = connected;
#ifdef MESH_IPV6
  this->work_ipv6_();
#endif
#ifndef MESH_IP_CLIENT_ONLY
  if (this->gateway_active_())
    this->work_probes_(connected);
  if (this->gateway_active_() && connected) {
    for (Peer &peer : this->peers_) {
      const uint32_t seen = peer.seen.load();
      const uint32_t now = now_ms();
      const bool fallback = peer.fallback.load() && uint32_t(now - seen) < PEER_LEASE_MS &&
                            this->peer_for_ip_(peer.ip.load(), true) == &peer - this->peers_ + 1;
      if (fallback && (!peer.announced || uint32_t(now - peer.last_announcement) >= 1000)) {
        this->announce_(peer.ip.load());
        peer.last_announcement = now;
      }
      peer.announced = fallback;
    }
  }
  ArpRequest arp;
  while (xQueueReceive(this->arp_queue_, &arp, 0) == pdTRUE) {
    if (connected && this->peer_for_ip_(arp.claimed_ip, true) != 0)
      this->arp_reply_(arp);
  }
#endif
  IpPacket &incoming = this->tcpip_rx_packet_;
#ifndef MESH_IP_CLIENT_ONLY
  IpFlowQueue::Key blocked_flows[RX_CAPACITY + 1]{};
  size_t blocked_count = 0;
#endif
  // Bound a service pass even when a congested flow is rotated for another
  // flow to proceed. Datagram ordering across the tunnel is not guaranteed.
  for (size_t budget = 0; budget < RX_CAPACITY + 1; ++budget) {
    if (!this->rx_pending_) {
      if (xQueueReceive(this->rx_queue_, &incoming, 0) != pdTRUE)
        break;
      this->rx_pending_ = true;
    }
    if (!this->transport_current_() || incoming.generation != this->gateway_generation_.load() ||
        !this->peer_epoch_current_(incoming.destination, incoming.peer_epoch)) {
      this->rx_pending_ = false;
      continue;
    }
#ifndef MESH_IP_CLIENT_ONLY
    const auto incoming_flow = IpFlowQueue::classify(incoming);
    bool blocked = false;
    for (size_t i = 0; i < blocked_count; ++i)
      blocked |= blocked_flows[i] == incoming_flow;
    if (blocked) {
      if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE)
        break;
      this->rx_pending_ = false;
      continue;
    }
#endif
#ifdef MESH_IPV6
    if (incoming.length >= 40 && (incoming.data[0] >> 4) == 6) {
      bool flow_blocked = false;
      if (!this->process_ipv6_(incoming, flow_blocked)) {
#ifndef MESH_IP_CLIENT_ONLY
        if (flow_blocked) {
          blocked_flows[blocked_count++] = incoming_flow;
          if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE)
            break;
          this->rx_pending_ = false;
          continue;
        }
#endif
        break;
      }
      this->rx_pending_ = false;
      continue;
    }
#endif
#ifndef MESH_IP_CLIENT_ONLY
    if (incoming.gateway_ingress &&
        (!this->gateway_active_() ||
         (!this->valid_dhcp_request_(incoming.destination, incoming.data, incoming.length) &&
          !this->gateway_source_valid_(incoming.destination, read_address(incoming.data + 12))))) {
      this->rx_pending_ = false;
      continue;
    }
#endif
    if (!incoming.gateway_ingress && read_address(incoming.data + 16) != address) {
      this->rx_pending_ = false;
      continue;
    }
#ifndef MESH_IP_CLIENT_ONLY
    // Forwarding to another mesh endpoint never enters lwIP. Keep the accepted
    // datagram in our RX storage until the bounded TX queue takes its copy;
    // allocating an unused pbuf here wastes heap and can stall mesh forwarding.
    if (incoming.gateway_ingress && read_address(incoming.data + 16) != address &&
        !this->valid_dhcp_request_(incoming.destination, incoming.data, incoming.length)) {
      const uint8_t mesh_destination = this->peer_for_ip_(read_address(incoming.data + 16), true);
      if (mesh_destination != 0) {
        if (!this->enqueue_(mesh_destination, incoming.data, incoming.length, false, incoming.destination,
                            incoming.peer_epoch)) {
          this->rx_retries_.fetch_add(1);
          blocked_flows[blocked_count++] = incoming_flow;
          if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE)
            break;
          this->rx_pending_ = false;
          continue;
        }
        this->mesh_rx_.fetch_add(1);
        this->rx_pending_ = false;
        continue;
      }
    }
#endif
    struct pbuf *packet = pbuf_alloc(PBUF_LINK, incoming.length, PBUF_RAM);
    if (packet == nullptr) {
      // Keep the already accepted datagram in the existing scratch. The mesh
      // worker's periodic update retries without spinning the TCP/IP task.
      this->rx_retries_.fetch_add(1);
      break;
    }
    pbuf_take(packet, incoming.data, incoming.length);
#ifndef MESH_IP_CLIENT_ONLY
    if (incoming.gateway_ingress) {
      ip4_addr_t destination{read_address(incoming.data + 16)};
      err_t result = ERR_RTE;
      if (this->valid_dhcp_request_(incoming.destination, incoming.data, incoming.length)) {
        if (connected && this->track_dhcp_request_(incoming.destination, incoming.data, incoming.length))
          result = etharp_output(this->station_netif_, packet, &destination);
      } else if (destination.addr == address) {
        this->rx_pending_ = false;
        if (ip4_input(packet, &this->virtual_netif_) == ERR_OK)
          this->mesh_rx_.fetch_add(1);
        continue;  // ip4_input owns the pbuf, including on error.
      } else {
        if (connected)
          result = etharp_output(this->station_netif_, packet, &destination);
      }
      pbuf_free(packet);
      if (result == ERR_MEM) {
        this->rx_retries_.fetch_add(1);
        // LAN backpressure belongs to this flow, unlike failure to allocate
        // any pbuf. Give other flows the same bounded opportunity as mesh TX.
        blocked_flows[blocked_count++] = incoming_flow;
        if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE)
          break;
        this->rx_pending_ = false;
        continue;
      }
      this->rx_pending_ = false;
      if (result == ERR_OK) {
        this->mesh_rx_.fetch_add(1);
        this->lan_tx_.fetch_add(1);
      } else
        this->queue_drops_.fetch_add(1);
    } else
#endif
    {
      this->rx_pending_ = false;
      if (ip4_input(packet, &this->virtual_netif_) == ERR_OK)
        this->mesh_rx_.fetch_add(1);
      // ip4_input consumes the pbuf regardless of protocol acceptance.
    }
  }
}

MeshIpNetif::Counters MeshIpNetif::counters() const {
  return {this->mesh_tx_.load(),           this->mesh_rx_.load(),   this->queue_drops_.load(),
          this->invalid_packets_.load(),   this->proxy_arp_.load(), this->lan_tx_.load(),
          this->flow_backpressure_.load(), this->rx_retries_.load()};
}

}  // namespace mesh_ip
