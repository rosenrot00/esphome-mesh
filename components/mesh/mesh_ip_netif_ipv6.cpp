#include "mesh_ip_netif.h"

#ifdef MESH_IPV6
#include "mesh_ip_ipv6.h"
#include <algorithm>
#include <cstring>
#include <esp_timer.h>
#include <lwip/ip6.h>
#include <lwip/mld6.h>
#include <lwip/nd6.h>
#include <lwip/pbuf.h>

namespace mesh_ip {
namespace {
uint32_t v6_now() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }
uint32_t v6_seconds() { return static_cast<uint32_t>(esp_timer_get_time() / 1000000); }
uint32_t be32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
struct V6PbufView {
  struct pbuf *packet;
  uint16_t offset, length;
};
bool v6_read_pbuf(const void *context, size_t offset, uint8_t *out, size_t count) {
  const auto &view = *static_cast<const V6PbufView *>(context);
  return offset <= view.length && count <= view.length - offset &&
         pbuf_copy_partial(view.packet, out, count, view.offset + offset) == count;
}
ip6_addr_t lwip_address(const Ipv6Address &address, const struct netif *netif) {
  ip6_addr_t result{};
  std::memcpy(result.addr, address.bytes.data(), 16);
  ip6_addr_assign_zone(&result, IP6_UNKNOWN, netif);
  return result;
}
Ipv6Address portable_address(const ip6_addr_t *address) {
  Ipv6Address result;
  std::memcpy(result.bytes.data(), address->addr, 16);
  return result;
}
bool same_addresses(const Ipv6AddressSnapshot &a, const Ipv6AddressSnapshot &b) {
  if (a.count != b.count)
    return false;
  for (size_t i = 0; i < a.count; ++i)
    if (a.addresses[i] != b.addresses[i])
      return false;
  return true;
}
bool contains(const Ipv6AddressSnapshot &snapshot, const Ipv6Address &address) {
  for (size_t i = 0; i < snapshot.count; ++i)
    if (snapshot.addresses[i] == address)
      return true;
  return false;
}
constexpr uint8_t CONFLICT_REPROBE = 0x80;
#ifndef MESH_IP_CLIENT_ONLY
class DriverPublicationGuard {
 public:
  explicit DriverPublicationGuard(std::atomic<bool> &busy) : busy_(busy), held_(!busy.exchange(true)) {}
  ~DriverPublicationGuard() { this->release(); }
  explicit operator bool() const { return this->held_; }
  void release() {
    if (this->held_) {
      this->busy_.store(false);
      this->held_ = false;
    }
  }

 private:
  std::atomic<bool> &busy_;
  bool held_;
};
#endif
}  // namespace

bool MeshIpNetif::read_ipv6_publication_(const Ipv6Publication &publication, Ipv6AddressSnapshot &out) {
  for (size_t attempt = 0; attempt < 3; ++attempt) {
    const uint32_t revision = publication.revision.load();
    if (revision & 1)
      continue;
    Ipv6AddressSnapshot snapshot;
    snapshot.generation = publication.generation.load();
    snapshot.peer_epoch = publication.peer_epoch.load();
    snapshot.count = publication.count.load();
    snapshot.preferred_mask = publication.preferred_mask.load();
    snapshot.ready = publication.ready.load();
    if (snapshot.count > Ipv6AddressSnapshot::CAPACITY)
      return false;
    for (size_t i = 0; i < snapshot.count; ++i) {
      for (size_t word = 0; word < 4; ++word) {
        const uint32_t value = publication.words[i][word].load();
        std::memcpy(snapshot.addresses[i].bytes.data() + word * 4, &value, 4);
      }
    }
    if (publication.revision.load() == revision) {
      out = snapshot;
      return true;
    }
  }
  return false;
}

void MeshIpNetif::publish_ipv6_(Ipv6Publication &publication, const Ipv6AddressSnapshot &snapshot) {
  publication.revision.fetch_add(1);
  publication.ready.store(false);
  publication.generation.store(snapshot.generation);
  publication.peer_epoch.store(snapshot.peer_epoch);
  for (size_t i = 0; i < snapshot.count; ++i) {
    for (size_t word = 0; word < 4; ++word) {
      uint32_t value;
      std::memcpy(&value, snapshot.addresses[i].bytes.data() + word * 4, 4);
      publication.words[i][word].store(value);
    }
  }
  publication.count.store(snapshot.count);
  publication.preferred_mask.store(snapshot.preferred_mask);
  publication.ready.store(snapshot.ready);
  publication.revision.fetch_add(1);
}

void MeshIpNetif::set_local_mac(const uint8_t mac[6]) {
  if (mac == nullptr || (mac[0] & 1))
    return;
  uint32_t low = 0, high = 0;
  std::memcpy(&low, mac, 4);
  std::memcpy(&high, mac + 4, 2);
  if ((low == 0 && high == 0) || this->ipv6_mac_ready_.load(std::memory_order_acquire))
    return;
  // Setup is the sole writer. The endpoint identity is immutable once complete;
  // configure() may already have scheduled the independent TCP/IP worker.
  this->ipv6_mac_low_.store(low, std::memory_order_relaxed);
  this->ipv6_mac_high_.store(high, std::memory_order_relaxed);
  this->ipv6_mac_ready_.store(true, std::memory_order_release);
  this->schedule_();
}

bool MeshIpNetif::ipv6_station_link_() const {
  return this->station_netif_ != nullptr && netif_is_up(this->station_netif_) && netif_is_link_up(this->station_netif_);
}

bool MeshIpNetif::local_ipv6_claim(Ipv6AddressSnapshot &snapshot) const {
  return this->configured_.load() && read_ipv6_publication_(this->ipv6_local_, snapshot);
}

bool MeshIpNetif::ipv6_available() const { return this->ipv6_ready_.load() && this->ipv6_forwarding_available_(); }

bool MeshIpNetif::ipv6_forwarding_available_() const {
  if (!this->configured_.load() || !this->ipv6_path_ready_.load())
    return false;
  if (this->ipv6_native_link_.load())
    return true;
  return this->role_current_() && this->mesh_reachable_.load() && this->gateway_id_.load() != this->node_id_ &&
         uint32_t(v6_now() - this->ipv6_grant_refreshed_.load()) < PEER_LEASE_MS;
}

bool MeshIpNetif::local_ipv6_snapshot(Ipv6AddressSnapshot &snapshot) const {
  if (!this->local_ipv6_claim(snapshot))
    return false;
  snapshot.ready = this->ipv6_available();
  return true;
}

bool MeshIpNetif::ipv6_peer_active_(uint8_t node_id) const {
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ || !this->gateway_active_())
    return false;
  const auto &peer = this->ipv6_peers_[node_id - 1];
  Ipv6AddressSnapshot requested;
  return peer.fallback.load() && uint32_t(v6_now() - peer.refreshed.load()) < PEER_LEASE_MS &&
         read_ipv6_publication_(peer.requested, requested) && this->peer_epoch_current_(node_id, requested.peer_epoch);
}

bool MeshIpNetif::peer_ipv6_snapshot(uint8_t node_id, Ipv6AddressSnapshot &snapshot) const {
  if (!this->ipv6_peer_active_(node_id) || !read_ipv6_publication_(this->ipv6_peers_[node_id - 1].granted, snapshot))
    return false;
  if (this->ipv6_peers_[node_id - 1].conflicts.load() != 0 || this->ipv6_peers_[node_id - 1].requalify.load())
    return false;
  Ipv6AddressSnapshot requested;
  return this->peer_epoch_current_(node_id, snapshot.peer_epoch) &&
         read_ipv6_publication_(this->ipv6_peers_[node_id - 1].requested, requested) &&
         requested.generation == snapshot.generation && requested.peer_epoch == snapshot.peer_epoch &&
         same_addresses(requested, snapshot);
}

bool MeshIpNetif::peer_ipv6_address_valid(uint8_t node_id, const Ipv6Address &address) const {
  Ipv6AddressSnapshot snapshot;
  return this->peer_ipv6_snapshot(node_id, snapshot) && snapshot.ready && contains(snapshot, address) &&
         this->ipv6_identity_valid_(node_id, address);
}

bool MeshIpNetif::ipv6_prefix_valid_(const Ipv6Address &address) const {
  if (address.link_local())
    return true;
  if (address.unspecified() || address.multicast())
    return false;
  uint32_t words[2];
  std::memcpy(words, address.bytes.data(), 8);
  for (const auto &prefix : this->ipv6_prefixes_) {
    const uint32_t revision = prefix.revision.load();
    if (revision & 1)
      continue;
    const uint32_t lifetime = prefix.lifetime.load(), started = prefix.started.load();
    const bool match = prefix.words[0].load() == words[0] && prefix.words[1].load() == words[1];
    if (prefix.revision.load() == revision && match && lifetime != 0 &&
        (lifetime == UINT32_MAX || uint32_t(v6_seconds() - started) < lifetime))
      return true;
  }
  return false;
}

bool MeshIpNetif::ipv6_identity_valid_(uint8_t node_id, const Ipv6Address &address) const {
  return this->ipv6_iid_valid_(node_id, address) && this->ipv6_prefix_valid_(address);
}

bool MeshIpNetif::ipv6_iid_valid_(uint8_t node_id, const Ipv6Address &address) const {
  if (node_id == 0 || node_id > mesh_limits::MAX_NODES || !this->peer_current_(node_id))
    return false;
  const auto &identity = this->identity_requests_[node_id - 1];
  const uint32_t epoch = identity.epoch.load(), low = identity.low.load(), high = identity.high.load();
  uint8_t mac[6];
  std::memcpy(mac, &low, 4);
  std::memcpy(mac + 4, &high, 2);
  return this->peer_epoch_current_(node_id, epoch) && address.matches_eui64(mac) && !address.unspecified() &&
         !address.multicast();
}

bool MeshIpNetif::apply_peer_ipv6_claim(uint8_t node_id, const Ipv6AddressSnapshot &snapshot, bool fallback) {
  if (!this->gateway_active_() || node_id == 0 || node_id > mesh_limits::MAX_NODES || node_id == this->node_id_ ||
      snapshot.count > Ipv6AddressSnapshot::CAPACITY || snapshot.generation == 0 || !this->peer_current_(node_id))
    return false;
  for (size_t i = 0; i < snapshot.count; ++i) {
    if (!this->ipv6_iid_valid_(node_id, snapshot.addresses[i]))
      return false;
    for (size_t j = 0; j < i; ++j)
      if (snapshot.addresses[i] == snapshot.addresses[j])
        return false;
  }
  Ipv6AddressSnapshot request = snapshot;
  request.ready = false;  // Only the LAN DAD observation can authorize it.
  request.peer_epoch = this->identity_requests_[node_id - 1].epoch.load();
  auto &peer = this->ipv6_peers_[node_id - 1];
#ifndef MESH_IP_CLIENT_ONLY
  DriverPublicationGuard publication(this->driver_tx_busy_);
  if (!publication)
    return false;
#endif
  Ipv6AddressSnapshot previous;
  if (read_ipv6_publication_(peer.requested, previous) && previous.generation != 0 &&
      previous.peer_epoch == request.peer_epoch) {
    const uint32_t advance = request.generation - previous.generation;
    if (advance == 0) {
      if (!same_addresses(previous, request) || peer.fallback.load() != fallback)
        return false;
    } else if (advance >= 0x80000000U)
      return false;
  }
  if (previous.generation != 0 && peer.fallback.load() != fallback)
    peer.requalify.store(true);
  const uint8_t observed_conflicts = peer.conflicts.load();
  uint8_t conflicts = 0;
  for (size_t i = 0; i < request.count; ++i)
    for (size_t j = 0; j < previous.count; ++j)
      if (request.addresses[i] == previous.addresses[j] && (observed_conflicts & (1U << j)))
        conflicts |= 1U << i;
  uint8_t pending = observed_conflicts;
  while (!peer.conflicts.compare_exchange_weak(pending, conflicts | (pending & CONFLICT_REPROBE))) {
  }
  publish_ipv6_(peer.requested, request);
  peer.fallback.store(fallback);
  peer.refreshed.store(v6_now());
  this->schedule_();
  return true;
}

bool MeshIpNetif::accept_ipv6_grant(uint8_t node_id, const Ipv6AddressSnapshot &snapshot) {
  Ipv6AddressSnapshot local;
  if (!snapshot.ready || node_id != this->gateway_id_.load() || !this->role_current_() ||
      !this->local_ipv6_claim(local) || snapshot.generation != local.generation || !same_addresses(snapshot, local))
    return false;
  Ipv6AddressSnapshot grant = snapshot;
  grant.peer_epoch = this->identity_requests_[node_id - 1].epoch.load();
  publish_ipv6_(this->ipv6_grant_request_, grant);
  this->ipv6_grant_refreshed_.store(v6_now());
  this->schedule_();
  return true;
}

void MeshIpNetif::reset_ipv6_peer_(size_t index) {
  auto &peer = this->ipv6_peers_[index];
  for (size_t i = 0; i < peer.active.count; ++i) {
    if (peer.joined[i] && this->station_netif_ != nullptr) {
      const auto group = lwip_address(peer.active.addresses[i].solicited_node(), this->station_netif_);
      mld6_leavegroup_netif(this->station_netif_, &group);
    }
  }
  peer.active = {};
  std::fill(std::begin(peer.probes), std::end(peer.probes), 0);
  std::fill(std::begin(peer.joined), std::end(peer.joined), false);
  peer.conflicts.store(0);
  peer.announcements = 0;
  peer.qualification_generation = 0;
  peer.requalify.store(false);
  publish_ipv6_(peer.granted, {});
}

void MeshIpNetif::observe_ipv6_ra_(const Ipv6PacketReader &reader, const Ipv6PacketInfo &info) {
  if (!info.nd || info.icmp_type != 134 || !info.source.link_local())
    return;
  uint8_t option[32];
  for (size_t offset = info.options_offset; offset < info.total_length;) {
    if (!reader.read(reader.context, offset, option, 2))
      return;
    const size_t length = size_t(option[1]) * 8;
    if (length == 0 || length > info.total_length - offset)
      return;
    if (option[0] == 3 && length == 32 && reader.read(reader.context, offset, option, 32) && option[2] == 64 &&
        (option[3] & 0x40) != 0 && be32(option + 8) <= be32(option + 4)) {
      Ipv6Address address;
      std::memcpy(address.bytes.data(), option + 16, 16);
      if (!address.link_local() && !address.multicast() && !address.unspecified()) {
        uint32_t words[2];
        std::memcpy(words, option + 16, 8);
        Ipv6Prefix *selected = nullptr;
        for (auto &prefix : this->ipv6_prefixes_) {
          if (prefix.words[0].load() == words[0] && prefix.words[1].load() == words[1]) {
            selected = &prefix;
            break;
          }
          const uint32_t life = prefix.lifetime.load();
          if (life == 0 || (life != UINT32_MAX && uint32_t(v6_seconds() - prefix.started.load()) >= life))
            selected = &prefix;
        }
        if (selected != nullptr) {
          selected->revision.fetch_add(1);
          selected->words[0].store(words[0]);
          selected->words[1].store(words[1]);
          selected->started.store(v6_seconds());
          selected->lifetime.store(be32(option + 4));
          selected->revision.fetch_add(1);
        }
      }
    }
    offset += length;
  }
}

void MeshIpNetif::observe_ipv6_conflict_(const Ipv6PacketInfo &info, const uint8_t source_mac[6]) {
  if (!info.nd || (info.icmp_type != 136 && !info.dad))
    return;
  const auto other_gateway = [&](uint8_t owner) {
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
      if (node == owner || !this->candidate_(node) || !this->peer_current_(node))
        continue;
      const auto &identity = this->identity_requests_[node - 1];
      const uint32_t low = identity.low.load(), high = identity.high.load();
      uint8_t mac[6];
      std::memcpy(mac, &low, 4);
      std::memcpy(mac + 4, &high, 2);
      if (std::memcmp(mac, source_mac, 6) == 0)
        return true;
    }
    return false;
  };
#ifndef MESH_IP_CLIENT_ONLY
  DriverPublicationGuard publication(this->driver_tx_busy_);
  if (!publication) {
    // The requested list may be changing. Never attribute a conflict to a
    // moving index or lose it: conservatively repeat DAD for its MAC owner.
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node)
      if (this->ipv6_iid_valid_(node, info.target) && !other_gateway(node))
        this->ipv6_peers_[node - 1].conflicts.fetch_or(CONFLICT_REPROBE);
    return;
  }
#endif
  for (size_t n = 0; n < mesh_limits::MAX_NODES; ++n) {
    Ipv6AddressSnapshot requested;
    if (!this->ipv6_peer_active_(n + 1) || !read_ipv6_publication_(this->ipv6_peers_[n].requested, requested))
      continue;
    // Another authenticated LAN edge may have a late proxy NA during gateway
    // handover. It is the same mesh owner, rather than a second LAN endpoint.
    if (other_gateway(n + 1))
      continue;
    for (size_t i = 0; i < requested.count; ++i)
      if (requested.addresses[i] == info.target)
        this->ipv6_peers_[n].conflicts.fetch_or(1U << i);
  }
}

uint8_t MeshIpNetif::peer_for_ipv6_(const Ipv6Address &address) const {
  if (address.multicast() || address.unspecified())
    return 0;
  for (size_t n = 0; n < mesh_limits::MAX_NODES; ++n)
    if (this->peer_ipv6_address_valid(n + 1, address))
      return n + 1;
  return 0;
}

bool MeshIpNetif::ipv6_local_address_(const Ipv6Address &address, bool tentative) const {
  (void) tentative;
  if (address.multicast())
    return true;
  Ipv6AddressSnapshot local;
  return this->local_ipv6_claim(local) && contains(local, address);
}

bool MeshIpNetif::ipv6_source_allowed_(uint8_t node_id, const Ipv6PacketInfo &info) const {
  if (!this->ipv6_peer_active_(node_id) || (info.nd && (info.icmp_type == 134 || info.icmp_type == 137)))
    return false;
  if (this->peer_ipv6_address_valid(node_id, info.source)) {
    if (info.nd && info.icmp_type == 136)
      return this->peer_ipv6_address_valid(node_id, info.target);
    return true;
  }
  // Bootstrap is deliberately limited to router solicitation and DAD from the
  // authenticated MAC's IID; it cannot carry arbitrary ordinary IPv6 traffic.
  if (info.nd && info.icmp_type == 133)
    return info.source.unspecified() || (info.source.link_local() && this->ipv6_identity_valid_(node_id, info.source));
  return info.dad && this->ipv6_identity_valid_(node_id, info.target);
}

bool MeshIpNetif::enqueue_ipv6_(uint8_t destination, struct pbuf *packet, uint16_t offset, uint16_t length,
                                bool from_driver) {
  const uint32_t generation = this->gateway_generation_.load();
  const uint32_t epoch =
      destination && destination <= mesh_limits::MAX_NODES ? this->identity_requests_[destination - 1].epoch.load() : 0;
  if (!this->transport_current_() || (!this->role_current_() && !this->gateway_active_()) ||
      !this->peer_epoch_current_(destination, epoch) || packet == nullptr || offset > packet->tot_len ||
      length > packet->tot_len - offset || length < 40 || length > MAX_PACKET_SIZE)
    return false;
#ifndef MESH_IP_CLIENT_ONLY
  if (from_driver && this->driver_tx_busy_.exchange(true))
    return false;
#else
  if (from_driver)
    return false;
#endif
  const V6PbufView view{packet, offset, length};
  Ipv6PacketInfo info;
  uint8_t prefix[64];
  const uint16_t bytes = std::min<size_t>(sizeof(prefix), length);
  bool result = false;
  if (inspect_ipv6({&view, v6_read_pbuf}, length, info) && pbuf_copy_partial(packet, prefix, bytes, offset) == bytes) {
    IpFlowQueue::Reservation reservation;
    IpPacket *out = this->reserve_outgoing_(IpFlowQueue::classify(destination, prefix, bytes), reservation);
    if (out != nullptr) {
      out->generation = generation;
      out->destination = destination;
      out->peer_epoch = epoch;
      out->ingress_source = 0;
      out->ingress_epoch = 0;
      out->gateway_ingress = false;
      out->length = length;
      result = this->commit_outgoing_(reservation, pbuf_copy_partial(packet, out->data, length, offset) == length);
    }
  } else
    this->invalid_packets_.fetch_add(1);
#ifndef MESH_IP_CLIENT_ONLY
  if (from_driver)
    this->driver_tx_busy_.store(false);
#endif
  if (result)
    this->mesh_tx_.fetch_add(1);
  else
    this->queue_drops_.fetch_add(1);
  return result;
}

err_t MeshIpNetif::netif_output_ipv6_(struct netif *interface, struct pbuf *packet, const ip6_addr_t *destination) {
  auto *self = instance_;
  if (self == nullptr || interface != &self->virtual_netif_ || packet == nullptr ||
      !self->ipv6_mac_ready_.load(std::memory_order_acquire))
    return ERR_RTE;
  if (self->ipv6_station_link_() && self->original_station_output_ipv6_ != nullptr)
    return self->original_station_output_ipv6_(self->station_netif_, packet, destination);
  if (!self->role_current_() || !self->mesh_reachable_.load() || self->node_id_ == self->gateway_id_.load())
    return ERR_RTE;
  const V6PbufView view{packet, 0, packet->tot_len};
  Ipv6PacketInfo info;
  if (!inspect_ipv6({&view, v6_read_pbuf}, packet->tot_len, info))
    return ERR_VAL;
  uint8_t mac[6];
  const uint32_t low = self->ipv6_mac_low_.load(), high = self->ipv6_mac_high_.load();
  std::memcpy(mac, &low, 4);
  std::memcpy(mac + 4, &high, 2);
  const bool bootstrap =
      info.nd && ((info.icmp_type == 133 &&
                   (info.source.unspecified() || (info.source.link_local() && info.source.matches_eui64(mac)))) ||
                  (info.dad && info.target.matches_eui64(mac)));
  if (!bootstrap && (!self->ipv6_forwarding_available_() || !self->ipv6_local_address_(info.source)))
    return ERR_RTE;
  return self->enqueue_ipv6_(self->gateway_id_.load(), packet, 0, packet->tot_len) ? ERR_OK : ERR_MEM;
}

#ifndef MESH_IP_CLIENT_ONLY
err_t MeshIpNetif::station_output_ipv6_(struct netif *interface, struct pbuf *packet, const ip6_addr_t *destination) {
  auto *self = instance_;
  if (self == nullptr || interface != self->station_netif_ || self->original_station_output_ipv6_ == nullptr)
    return ERR_IF;
  const uint8_t peer = self->peer_for_ipv6_(portable_address(destination));
  if (peer != 0)
    return self->enqueue_ipv6_(peer, packet, 0, packet->tot_len) ? ERR_OK : ERR_MEM;
  return self->original_station_output_ipv6_(interface, packet, destination);
}

bool MeshIpNetif::station_input_ipv6_(struct pbuf *packet, bool &consume) {
  consume = false;
  if (packet == nullptr || packet->tot_len < 54 || !this->ipv6_station_link_())
    return false;
  uint8_t ethernet[14];
  if (pbuf_copy_partial(packet, ethernet, 14, 0) != 14 || ethernet[12] != 0x86 || ethernet[13] != 0xdd)
    return false;
  // Do not relay the gateway's own reflected multicast back into the mesh.
  if (std::memcmp(ethernet + 6, this->station_netif_->hwaddr, 6) == 0)
    return false;
  uint8_t header[40];
  if (pbuf_copy_partial(packet, header, 40, 14) != 40)
    return false;
  const size_t length = 40 + (size_t(header[4]) << 8 | header[5]);
  if (length > MAX_PACKET_SIZE || length > packet->tot_len - 14)
    return false;
  const V6PbufView view{packet, 14, static_cast<uint16_t>(length)};
  Ipv6PacketInfo info;
  if (!inspect_ipv6({&view, v6_read_pbuf}, length, info)) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  // Prefix authority comes only from the physical LAN, never mesh packets.
  this->observe_ipv6_ra_({&view, v6_read_pbuf}, info);
  this->observe_ipv6_conflict_(info, ethernet + 6);
  if (!this->gateway_active_())
    return false;
  const uint8_t peer = this->peer_for_ipv6_(info.destination);
  if (peer != 0) {
    this->enqueue_ipv6_(peer, packet, 14, length, true);
    consume = true;
    return true;
  }
  if (!info.destination.multicast())
    return false;
  bool relayed = false;
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    if (!this->ipv6_peer_active_(node))
      continue;
    Ipv6AddressSnapshot claim;
    if (!read_ipv6_publication_(this->ipv6_peers_[node - 1].requested, claim))
      continue;
    const bool targeted_nd = info.nd && (info.icmp_type == 135 || info.icmp_type == 136);
    if (targeted_nd && !contains(claim, info.target))
      continue;
    relayed |= this->enqueue_ipv6_(node, packet, 14, length, true);
  }
  return relayed;
}
#endif

bool MeshIpNetif::deliver_ipv6_(uint8_t source, const uint8_t *packet, size_t length) {
  const uint32_t generation = this->gateway_generation_.load();
  const uint32_t epoch =
      source && source <= mesh_limits::MAX_NODES ? this->identity_requests_[source - 1].epoch.load() : 0;
  Ipv6PacketInfo info;
  if (!this->configured_.load() || !this->transport_current_() || !this->peer_epoch_current_(source, epoch) ||
      source == this->node_id_ || !inspect_ipv6(packet, length, info))
    return false;
  const bool gateway_ingress = this->gateway_active_() && this->ipv6_source_allowed_(source, info);
  if (!gateway_ingress && (source != this->gateway_id_.load() || !this->role_current_() ||
                           this->ipv6_native_link_.load() || !this->ipv6_local_address_(info.destination, true))) {
    this->invalid_packets_.fetch_add(1);
    return false;
  }
  IpPacket incoming;
  incoming.generation = generation;
  incoming.peer_epoch = epoch;
  incoming.destination = source;
  incoming.gateway_ingress = gateway_ingress;
  incoming.length = length;
  std::memcpy(incoming.data, packet, length);
  if (xQueueSend(this->rx_queue_, &incoming, 0) != pdTRUE) {
    this->queue_drops_.fetch_add(1);
    return false;
  }
  this->schedule_();
  return true;
}

bool MeshIpNetif::send_ipv6_dad_(const Ipv6Address &address) {
  if (!this->ipv6_station_link_() || this->original_station_output_ipv6_ == nullptr)
    return false;
  uint8_t bytes[64]{};
  bytes[0] = 0x60;
  bytes[5] = 24;
  bytes[6] = 58;
  bytes[7] = 255;
  const auto group = address.solicited_node();
  std::memcpy(bytes + 24, group.bytes.data(), 16);
  bytes[40] = 135;
  std::memcpy(bytes + 48, address.bytes.data(), 16);
  if (!finalize_icmpv6_checksum(bytes, sizeof(bytes)))
    return false;
  auto *packet = pbuf_alloc(PBUF_LINK, sizeof(bytes), PBUF_RAM);
  if (packet == nullptr)
    return false;
  pbuf_take(packet, bytes, sizeof(bytes));
  const auto destination = lwip_address(group, this->station_netif_);
  const err_t result = this->original_station_output_ipv6_(this->station_netif_, packet, &destination);
  pbuf_free(packet);
  return result == ERR_OK;
}

bool MeshIpNetif::send_ipv6_rs_() {
  if (!this->ipv6_station_link_() || this->original_station_output_ipv6_ == nullptr)
    return false;
  uint8_t bytes[48]{};
  bytes[0] = 0x60;
  bytes[5] = 8;
  bytes[6] = 58;
  bytes[7] = 255;
  bytes[24] = 0xff;
  bytes[25] = 2;
  bytes[39] = 2;
  bytes[40] = 133;
  if (!finalize_icmpv6_checksum(bytes, sizeof(bytes)))
    return false;
  auto *packet = pbuf_alloc(PBUF_LINK, sizeof(bytes), PBUF_RAM);
  if (packet == nullptr)
    return false;
  pbuf_take(packet, bytes, sizeof(bytes));
  Ipv6Address group;
  std::memcpy(group.bytes.data(), bytes + 24, 16);
  const auto destination = lwip_address(group, this->station_netif_);
  const err_t result = this->original_station_output_ipv6_(this->station_netif_, packet, &destination);
  pbuf_free(packet);
  return result == ERR_OK;
}

bool MeshIpNetif::send_ipv6_na_(const Ipv6Address &address) {
  if (!this->ipv6_station_link_() || this->original_station_output_ipv6_ == nullptr)
    return false;
  uint8_t bytes[72]{};
  bytes[0] = 0x60;
  bytes[5] = 32;
  bytes[6] = 58;
  bytes[7] = 255;
  std::memcpy(bytes + 8, address.bytes.data(), 16);
  bytes[24] = 0xff;
  bytes[25] = 2;
  bytes[39] = 1;
  bytes[40] = 136;
  bytes[44] = 0x20;  // unsolicited Override, never Router/Solicited.
  std::memcpy(bytes + 48, address.bytes.data(), 16);
  bytes[64] = 2;
  bytes[65] = 1;
  std::memcpy(bytes + 66, this->station_netif_->hwaddr, 6);
  if (!finalize_icmpv6_checksum(bytes, sizeof(bytes)))
    return false;
  auto *packet = pbuf_alloc(PBUF_LINK, sizeof(bytes), PBUF_RAM);
  if (packet == nullptr)
    return false;
  pbuf_take(packet, bytes, sizeof(bytes));
  Ipv6Address group;
  std::memcpy(group.bytes.data(), bytes + 24, 16);
  const auto destination = lwip_address(group, this->station_netif_);
  const err_t result = this->original_station_output_ipv6_(this->station_netif_, packet, &destination);
  pbuf_free(packet);
  return result == ERR_OK;
}

void MeshIpNetif::work_ipv6_() {
  if (!this->virtual_added_ || !this->ipv6_mac_ready_.load(std::memory_order_acquire))
    return;
  const uint32_t low = this->ipv6_mac_low_.load(), high = this->ipv6_mac_high_.load();
  if (low == 0 && high == 0)
    return;
  uint8_t mac[6];
  std::memcpy(mac, &low, 4);
  std::memcpy(mac + 4, &high, 2);
  const bool native = this->ipv6_station_link_();
  const bool mode_changed = !this->ipv6_initialized_ || native != this->ipv6_was_native_;
  auto &interface = this->virtual_netif_;
  if (mode_changed) {
    for (size_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; ++i)
      netif_ip6_addr_set_state(&interface, i, IP6_ADDR_INVALID);
    interface.hwaddr_len = 6;
    std::memcpy(interface.hwaddr, mac, 6);
    netif_set_ip6_autoconfig_enabled(&interface, !native);
    if (!native) {
      netif_create_ip6_linklocal_address(&interface, 1);
#ifdef MESH_HAS_ETHERNET
      // Ethernet's MAC is not the mesh identity. Its SLAAC addresses cannot
      // be claimed by the station-MAC identity after the cable is lost.
      if (this->applied_native_uplink_.load() == NativeUplink::NATIVE_UPLINK_ETHERNET)
        this->ipv6_previous_local_ = {};
#endif
      // Retained native SLAAC addresses keep only their remaining lifetimes,
      // and undergo DAD through the mesh before the gateway grants ownership.
      for (size_t i = 0; i < this->ipv6_previous_local_.count; ++i) {
        const auto &address = this->ipv6_previous_local_.addresses[i];
        if (address.link_local())
          continue;
        s8_t slot = -1;
        const auto converted = lwip_address(address, &interface);
        const uint32_t elapsed = uint32_t(v6_seconds() - this->ipv6_lifetime_saved_);
        const auto remaining = [elapsed](uint32_t life) {
          return life == UINT32_MAX ? life : (life > elapsed ? life - elapsed : 0U);
        };
        const uint32_t valid = remaining(this->ipv6_saved_valid_life_[i]);
        if (valid != 0 && netif_add_ip6_address(&interface, &converted, &slot) == ERR_OK && slot >= 0) {
          netif_ip6_addr_set_valid_life(&interface, slot, valid);
          netif_ip6_addr_set_pref_life(&interface, slot, remaining(this->ipv6_saved_pref_life_[i]));
          netif_ip6_addr_set_state(&interface, slot, IP6_ADDR_TENTATIVE);
        }
      }
      netif_set_up(&interface);
      netif_set_link_up(&interface);
      nd6_restart_netif(&interface);
    }
    this->ipv6_initialized_ = true;
    this->ipv6_was_native_ = native;
  }
  Ipv6AddressSnapshot local;
  const struct netif *source = native ? this->station_netif_ : &interface;
  for (size_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES && local.count < Ipv6AddressSnapshot::CAPACITY; ++i) {
    const uint8_t state = netif_ip6_addr_state(source, i);
    if (!ip6_addr_isvalid(state))
      continue;
    const auto address = portable_address(netif_ip6_addr(source, i));
    if (address.unspecified() || address.multicast() || !address.matches_eui64(mac))
      continue;
    if (native) {
      this->ipv6_saved_valid_life_[local.count] =
          address.link_local() ? UINT32_MAX : netif_ip6_addr_valid_life(source, i);
      this->ipv6_saved_pref_life_[local.count] =
          address.link_local() ? UINT32_MAX : netif_ip6_addr_pref_life(source, i);
    }
    if (ip6_addr_ispreferred(state))
      local.preferred_mask |= 1U << local.count;
    local.addresses[local.count++] = address;
  }
  if (native)
    this->ipv6_lifetime_saved_ = v6_seconds();
  this->ipv6_native_link_.store(native);
  const uint32_t generation = this->gateway_generation_.load();
  const bool gateway_changed = generation != this->ipv6_gateway_generation_;
  if (mode_changed || gateway_changed || !same_addresses(local, this->ipv6_previous_local_)) {
    // The mesh worker reserves the next nonzero revision for an old-root
    // withdrawal. Even coalesced gateway switches must publish beyond it.
    if (gateway_changed && ++this->ipv6_local_generation_ == 0)
      ++this->ipv6_local_generation_;
    if (++this->ipv6_local_generation_ == 0)
      ++this->ipv6_local_generation_;
    this->ipv6_gateway_generation_ = generation;
    this->ipv6_ready_.store(false);
    this->ipv6_path_ready_.store(false);
    if (native) {
      this->ipv6_native_announcements_ = 3;
      this->ipv6_last_native_announcement_ = v6_now() - 1000;
    }
  }
  local.generation = this->ipv6_local_generation_;
  local.ready = local.count != 0;
  this->ipv6_previous_local_ = local;
  publish_ipv6_(this->ipv6_local_, local);
  size_t global = 0;
  for (size_t i = 0; i < local.count; ++i)
    global += !local.addresses[i].link_local() && (local.preferred_mask & (1U << i)) != 0;
#ifdef MESH_MIN_IPV6_ADDR_COUNT
  const bool minimum = global >= MESH_MIN_IPV6_ADDR_COUNT;
#else
  const bool minimum = true;
#endif
  (void) global;
  this->ipv6_native_ready_.store(native && local.count != 0 && minimum);
  Ipv6AddressSnapshot grant;
  const uint8_t gateway = this->gateway_id_.load();
  const bool granted = gateway && this->role_current_() && read_ipv6_publication_(this->ipv6_grant_request_, grant) &&
                       this->peer_epoch_current_(gateway, grant.peer_epoch) && grant.ready &&
                       grant.generation == local.generation && same_addresses(grant, local);
  this->ipv6_path_ready_.store(local.count != 0 && (native || granted));
  this->ipv6_ready_.store(minimum && this->ipv6_path_ready_.load());
  if (native && this->ipv6_native_announcements_ != 0 &&
      uint32_t(v6_now() - this->ipv6_last_native_announcement_) >= 1000) {
    bool sent = local.count != 0;
    for (size_t i = 0; i < local.count; ++i)
      sent &= this->send_ipv6_na_(local.addresses[i]);
    if (sent) {
      --this->ipv6_native_announcements_;
      this->ipv6_last_native_announcement_ = v6_now();
    }
  }
  if (!native && this->role_current_() && this->mesh_reachable_.load())
    netif_set_default(&interface);
  else if (native && netif_default == &interface)
    netif_set_default(this->station_netif_);
  for (size_t n = 0; n < mesh_limits::MAX_NODES; ++n) {
    auto &peer = this->ipv6_peers_[n];
#ifndef MESH_IP_CLIENT_ONLY
    DriverPublicationGuard publication(this->driver_tx_busy_);
    if (!publication)
      continue;
#endif
    Ipv6AddressSnapshot request;
    if (!this->ipv6_peer_active_(n + 1) || !read_ipv6_publication_(peer.requested, request) ||
        !this->peer_epoch_current_(n + 1, request.peer_epoch)) {
      if (peer.active.generation != 0)
        this->reset_ipv6_peer_(n);
      continue;
    }
    const bool requalify = peer.requalify.exchange(false);
    const bool same_owner =
        peer.active.peer_epoch == request.peer_epoch && peer.qualification_generation == generation && !requalify;
    if (request.generation != peer.active.generation || request.peer_epoch != peer.active.peer_epoch ||
        !same_addresses(request, peer.active) || !same_owner) {
      uint32_t started[Ipv6AddressSnapshot::CAPACITY]{};
      uint8_t probes[Ipv6AddressSnapshot::CAPACITY]{};
      bool joined[Ipv6AddressSnapshot::CAPACITY]{};
      for (size_t old = 0; old < peer.active.count; ++old) {
        size_t current = request.count;
        if (same_owner)
          for (size_t i = 0; i < request.count; ++i)
            if (peer.active.addresses[old] == request.addresses[i]) {
              current = i;
              break;
            }
        if (current != request.count) {
          started[current] = peer.probe_started[old];
          probes[current] = peer.probes[old];
          joined[current] = peer.joined[old];
        } else if (peer.joined[old] && this->station_netif_ != nullptr) {
          const auto group = lwip_address(peer.active.addresses[old].solicited_node(), this->station_netif_);
          mld6_leavegroup_netif(this->station_netif_, &group);
        }
      }
      std::copy(std::begin(started), std::end(started), std::begin(peer.probe_started));
      std::copy(std::begin(probes), std::end(probes), std::begin(peer.probes));
      std::copy(std::begin(joined), std::end(joined), std::begin(peer.joined));
      if (!same_owner)
        peer.conflicts.fetch_and(CONFLICT_REPROBE);
      peer.active = request;
      peer.qualification_generation = generation;
      peer.announcements = 0;
    }
    if (peer.conflicts.fetch_and(static_cast<uint8_t>(~CONFLICT_REPROBE)) & CONFLICT_REPROBE) {
      std::fill(std::begin(peer.probes), std::end(peer.probes), 0);
      std::fill(std::begin(peer.probe_started), std::end(peer.probe_started), 0);
    }
#ifndef MESH_IP_CLIENT_ONLY
    publication.release();
#endif
    bool ready = request.count != 0;
    bool missing_prefix = false;
    for (size_t i = 0; i < request.count; ++i) {
      if (!this->ipv6_identity_valid_(n + 1, request.addresses[i])) {
        peer.probes[i] = 0;
        ready = false;
        missing_prefix = true;
        continue;
      }
      if (!peer.joined[i]) {
        const auto group = lwip_address(request.addresses[i].solicited_node(), this->station_netif_);
        peer.joined[i] = mld6_joingroup_netif(this->station_netif_, &group) == ERR_OK;
      }
      if (!peer.joined[i] || (peer.conflicts.load() & (1U << i))) {
        ready = false;
        continue;
      }
      const uint32_t now = v6_now();
      if (peer.probes[i] < 3 && (peer.probes[i] == 0 || uint32_t(now - peer.probe_started[i]) >= 1000)) {
        if (this->send_ipv6_dad_(request.addresses[i])) {
          ++peer.probes[i];
          peer.probe_started[i] = now;
        }
      }
      if (peer.probes[i] != 3 || uint32_t(now - peer.probe_started[i]) < 1000)
        ready = false;
    }
    if (missing_prefix && uint32_t(v6_now() - this->ipv6_last_rs_) >= 1000 && this->send_ipv6_rs_())
      this->ipv6_last_rs_ = v6_now();
#ifndef MESH_IP_CLIENT_ONLY
    DriverPublicationGuard grant_publication(this->driver_tx_busy_);
    if (!grant_publication)
      continue;
#endif
    Ipv6AddressSnapshot current;
    if (!this->ipv6_peer_active_(n + 1) || !read_ipv6_publication_(peer.requested, current) ||
        current.generation != request.generation || current.peer_epoch != request.peer_epoch ||
        !same_addresses(current, request) || peer.qualification_generation != this->gateway_generation_.load())
      continue;
    if (peer.conflicts.load() != 0 || peer.requalify.load())
      ready = false;
    Ipv6AddressSnapshot previous;
    if (ready && (!read_ipv6_publication_(peer.granted, previous) || !previous.ready)) {
      peer.announcements = 3;
      peer.last_announcement = v6_now() - 1000;
    }
    request.ready = ready;
    publish_ipv6_(peer.granted, request);
#ifndef MESH_IP_CLIENT_ONLY
    grant_publication.release();
#endif
    if (ready && peer.announcements != 0 && uint32_t(v6_now() - peer.last_announcement) >= 1000) {
      bool sent = true;
      for (size_t i = 0; i < request.count; ++i)
        sent &= this->send_ipv6_na_(request.addresses[i]);
      if (sent) {
        --peer.announcements;
        peer.last_announcement = v6_now();
      }
    }
  }
}

bool MeshIpNetif::process_ipv6_(IpPacket &incoming, bool &flow_blocked) {
  flow_blocked = false;
  Ipv6PacketInfo info;
  if (!inspect_ipv6(incoming.data, incoming.length, info)) {
    this->invalid_packets_.fetch_add(1);
    return true;
  }
  if (incoming.gateway_ingress) {
    if (!this->gateway_active_() || !this->ipv6_source_allowed_(incoming.destination, info))
      return true;
    const uint8_t other = this->peer_for_ipv6_(info.destination);
    if (other != 0 && other != incoming.destination) {
      if (!this->enqueue_(other, incoming.data, incoming.length, false, incoming.destination, incoming.peer_epoch)) {
        flow_blocked = true;
        this->rx_retries_.fetch_add(1);
        return false;
      }
      this->mesh_rx_.fetch_add(1);
      return true;
    }
    if (info.nd && !rewrite_nd_link_address(incoming.data, incoming.length, this->station_netif_->hwaddr))
      return true;
  } else if (incoming.destination != this->gateway_id_.load() || this->ipv6_station_link_() ||
             !this->ipv6_local_address_(info.destination, true))
    return true;
  auto *packet = pbuf_alloc(PBUF_LINK, incoming.length, PBUF_RAM);
  if (packet == nullptr) {
    this->rx_retries_.fetch_add(1);
    return false;
  }
  pbuf_take(packet, incoming.data, incoming.length);
  if (!incoming.gateway_ingress) {
    ip6_input(packet, &this->virtual_netif_);
    this->mesh_rx_.fetch_add(1);
    return true;
  }
  const bool local = this->ipv6_local_address_(info.destination);
  err_t result = ERR_OK;
  if (!local || info.destination.multicast()) {
    const auto destination = lwip_address(info.destination, this->station_netif_);
    result = this->original_station_output_ipv6_ == nullptr
                 ? ERR_RTE
                 : this->original_station_output_ipv6_(this->station_netif_, packet, &destination);
    if (result == ERR_MEM) {
      pbuf_free(packet);
      this->rx_retries_.fetch_add(1);
      flow_blocked = true;
      return false;
    }
    if (result == ERR_OK)
      this->lan_tx_.fetch_add(1);
  }
  if (info.destination.multicast()) {
    // A physical AP need not reflect sender multicast; relay directly once to
    // the other children selected to this LAN edge. Their input never relays.
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node)
      if (node != incoming.destination && this->ipv6_peer_active_(node))
        this->enqueue_(node, incoming.data, incoming.length, true, incoming.destination, incoming.peer_epoch);
  }
  if (local)
    ip6_input(packet, this->station_netif_);
  else
    pbuf_free(packet);
  if (result == ERR_OK)
    this->mesh_rx_.fetch_add(1);
  else
    this->queue_drops_.fetch_add(1);
  return true;
}
}  // namespace mesh_ip
#endif
