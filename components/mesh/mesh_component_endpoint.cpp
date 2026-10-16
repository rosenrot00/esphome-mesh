#include "mesh_component.h"
#include "esphome/core/hal.h"

#include <cstring>
#include <esp_random.h>
#include <lwip/def.h>

namespace esphome::mesh {
namespace {
constexpr uint8_t WITNESS = ::mesh_ip::LEASE_WITNESS_CONTROL;
constexpr uint8_t NEED_WITNESS = 13;
uint32_t read_le(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
#ifndef MESH_IP_CLIENT_ONLY
void write_le(uint8_t *p, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    p[i] = value >> (8 * i);
}
#endif
uint32_t read_be(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
#ifndef MESH_IP_CLIENT_ONLY
void write_be(uint8_t *p, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    p[i] = value >> (24 - 8 * i);
}
#endif
}  // namespace

#ifndef USE_MESH_AUTO
uint64_t MeshComponent::manual_session_(void *context, ::mesh_core::NodeId node) {
  return static_cast<MeshComponent *>(context)->identity_session_(node);
}

void MeshComponent::manual_session_receive_(const ::mesh_core::Frame &frame) {
  ::mesh_session::Message message;
  if (!::mesh_session::decode(frame.payload, frame.payload_length, frame.source, frame.destination, message))
    return;
  uint64_t nonce;
  do {
    nonce = (uint64_t(esp_random()) << 32) | esp_random();
  } while (nonce == 0);
  // The registry closes a changed proved session immediately. Platform work is
  // deferred until Core::receive has returned; callbacks never reenter Core.
  this->manual_sessions_.receive(frame.source, frame.destination, message, millis(), nonce);
}

void MeshComponent::manual_session_tick_(uint32_t now) {
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    if (node == this->node_id_ || !this->allowed_(node))
      continue;
    const uint64_t boot = this->manual_sessions_.proved_boot(node);
    if (boot == 0 || this->manual_sessions_.session(node) != 0)
      continue;
    auto &binding = this->manual_bindings_[node - 1];
    if (binding.boot != boot) {
      binding.boot = boot;
      if (++this->manual_epoch_ == 0)
        ++this->manual_epoch_;
      binding.epoch = this->manual_epoch_;
      binding.netif_done = binding.mdns_done = !this->ip_enabled();
      this->ip_delivery_.reset_peer(node);
      this->endpoint_challenges_.reset_peer(node);
      this->endpoint_replies_[node - 1] = 0;
#ifndef MESH_IP_CLIENT_ONLY
      this->pending_endpoint_witness_[node - 1] = {};
      this->pending_lease_results_[node - 1] = {};
      this->pending_ip_acks_[node - 1] = {};
#endif
      for (auto &pending : this->pending_probes_)
        if (pending.peer == node)
          pending = {};
      if (this->benchmark_peer_ == node)
        this->benchmark_active_ = false;
    }
    if (this->ip_enabled()) {
      // Only YAML-pinned identities reach the platform. A relayed boot claim
      // never supplies or replaces a DHCP/mDNS MAC mapping.
      bool has_mac = false;
      for (uint8_t byte : binding.mac)
        has_mac |= byte != 0;
      if (!has_mac)
        continue;  // Invalid generated input stays closed.
      if (!binding.netif_done)
        binding.netif_done = this->ip_netif_.update_peer_identity(node, binding.mac.data(), binding.epoch);
#ifdef USE_MESH_DISCOVERY
      if (!binding.mdns_done)
        binding.mdns_done = this->ip_mdns_.update_peer_identity(node, binding.mac.data(), binding.epoch);
#else
      binding.mdns_done = true;
#endif
    }
    if (binding.netif_done && binding.mdns_done)
      this->manual_sessions_.activate(node, boot);
  }
  // One bounded bootstrap contract, no packet buffering or route prerequisite.
  // Failed queue admission does not mark a challenge as transmitted.
  for (unsigned budget = 0; budget < 2 && this->transport_has_room_(); ++budget) {
    ::mesh_session::ManualBootSessionRegistry::Outgoing outgoing;
    if (!this->manual_sessions_.next_outgoing(now, outgoing))
      break;
    uint8_t wire[::mesh_session::WIRE_SIZE];
    size_t length;
    if (!::mesh_session::encode(outgoing.message, this->node_id_, outgoing.destination, wire, sizeof(wire), length) ||
        !this->core_->send_bootstrap(outgoing.destination, ++this->sequence_, wire, length, now))
      break;
    this->manual_sessions_.sent(outgoing, now);
  }
}
#endif

bool MeshComponent::endpoint_deliver_(const ::mesh_core::Frame &frame) {
  if (frame.payload_length < 2)
    return false;
  const uint8_t command = frame.payload[1];
  if (frame.payload[0] != 1 && !(command == WITNESS && frame.payload[0] == 2))
    return false;
  if (command == ::mesh_ip::ENDPOINT_CHALLENGE_CONTROL) {
    uint64_t nonce;
    if (this->gateway_candidate_(frame.source) &&
        ::mesh_ip::decode_endpoint_challenge(frame.payload, frame.payload_length, nonce))
      this->endpoint_replies_[frame.source - 1] = nonce;
    return true;
  }
  if (command == ::mesh_ip::ENDPOINT_RESPONSE_CONTROL) {
#ifndef MESH_IP_CLIENT_ONLY
    ::mesh_ip::EndpointAdvertisement endpoint;
    uint32_t age;
    if (!this->gateway_service_() || !this->last_direct_uplink_ ||
        !::mesh_ip::decode_endpoint_advertisement(frame.payload, frame.payload_length, endpoint))
      return true;
#ifndef USE_MESH_AUTO
    if (endpoint.session == 0 || endpoint.session != frame.source_session)
      return true;
#endif
    if (!this->endpoint_challenges_.consume(frame.source, endpoint.nonce, millis(), age))
      return true;
    auto &pending_witness = this->pending_endpoint_witness_[frame.source - 1];
    // A later endpoint proof supersedes an unsent native-rejoin ACK too.
    this->pending_ip_acks_[frame.source - 1].used = false;
    bool active = false;
    const uint32_t address = lwip_htonl(endpoint.address);
    uint32_t active_address = address;
    if (endpoint.mode == ::mesh_ip::EndpointMode::MESH) {
      const uint32_t budget = ::mesh_ip::ChallengeRegistry::freshness_budget(endpoint.remaining_seconds, age);
      active = budget != 0 && this->ip_netif_.authorize_endpoint(frame.source, address, endpoint.lease_id,
                                                                 endpoint.remaining_seconds, budget);
      if (!active && !this->ip_netif_.has_lease_witness(frame.source, address, endpoint.lease_id)) {
        // ACK evidence travels independently of the client's proof. Allow
        // periodic gateway witness exports to arrive before requesting a new
        // DHCP renewal; repeated proofs must not postpone this wait forever.
        if (!pending_witness.used || pending_witness.address != endpoint.address ||
            pending_witness.lease_id != endpoint.lease_id)
          pending_witness.started = millis();
        pending_witness.used = true;
        pending_witness.address = endpoint.address;
        pending_witness.lease_id = endpoint.lease_id;
      } else {
        pending_witness.used = false;
      }
      // The nonblocking Wi-Fi driver guard can temporarily reject a valid
      // grant. Preserve an existing fresh route/advertisement and retry with
      // the next challenge instead of mistaking congestion for lease loss.
      if (!active && this->ip_netif_.peer_mesh_address(frame.source) == address)
        active = true;
    } else if (this->ip_netif_.withdraw_endpoint(frame.source)) {
      pending_witness.used = false;
      if (endpoint.mode == ::mesh_ip::EndpointMode::QUIET && address != 0) {
        // ACK only a challenged withdrawal. The transport task sends it after
        // delegated mDNS has also been withdrawn, outside the core callback.
        auto &ack = this->pending_ip_acks_[frame.source - 1];
        ack.payload[0] = 1;
        ack.payload[1] = 4;
        std::memcpy(ack.payload + 2, &address, sizeof(address));
        ack.payload[6] = 0;
        write_le(ack.payload + 7, endpoint.lease_id);
        ack.used = true;
      }
    } else {
      pending_witness.used = false;
      // A busy driver must not turn an attempted withdrawal into an ACK.
      // Keep the existing bounded grant until the next fresh challenge.
      active_address = this->ip_netif_.peer_mesh_address(frame.source);
      active = active_address != 0;
    }
#ifdef USE_MESH_DISCOVERY
    this->ip_mdns_.note_status(frame.source, active ? active_address : 0, active);
#endif
#endif
    return true;
  }
  if (command == WITNESS) {
#ifndef MESH_IP_CLIENT_ONLY
    constexpr auto mode = ::mesh_ip::WitnessIdentityMode::SESSION_BOUND;
    ::mesh_ip::LeaseWitness witness;
    if (!this->gateway_service_() || !this->gateway_candidate_(frame.source) ||
        !::mesh_ip::decode_lease_witness(frame.payload, frame.payload_length, mode, witness) ||
        !this->allowed_(witness.node_id) || witness.node_id == this->node_id_)
      return true;
    const uint64_t subject_session = this->identity_session_(witness.node_id);
    if (::mesh_ip::witness_matches_subject(witness, mode, subject_session))
      this->ip_netif_.install_peer_witness(witness.node_id, lwip_htonl(witness.address), witness.lease_id,
                                           witness.remaining_seconds);
#endif
    return true;
  }
  if (command == NEED_WITNESS) {
    if (this->gateway_candidate_(frame.source) && frame.payload_length == 10 && this->dhcp_lease_installed_ &&
        read_be(frame.payload + 2) == this->dhcp_client_.lease().address &&
        read_le(frame.payload + 6) == this->dhcp_client_.lease_xid() &&
        this->dhcp_client_.state() == ::mesh_ip::DhcpState::BOUND &&
        uint32_t(millis() - this->last_witness_refresh_) >= 2000) {
      // A newly booted gateway may have missed every original ACK witness.
      // Preserve the client's address and lease; obtain proof for this cold
      // gateway through an ordinary renewal, without ownership handover.
      this->last_witness_refresh_ = millis();
      this->gateway_revalidate_ = true;
    }
    return true;
  }
  return false;
}

void MeshComponent::endpoint_tick_(uint32_t now, bool direct) {
  if (this->ip_gateways_ == 0)
    return;
  for (uint8_t gateway = 1; gateway <= mesh_limits::MAX_NODES; gateway++) {
    const uint64_t nonce = this->endpoint_replies_[gateway - 1];
    if (nonce == 0 || !this->transport_has_room_())
      continue;
    ::mesh_ip::EndpointAdvertisement endpoint{};
    endpoint.nonce = nonce;
    endpoint.session = this->endpoint_session_;
    if (this->ip_handover_.quiet()) {
      endpoint.mode = ::mesh_ip::EndpointMode::QUIET;
      endpoint.address = lwip_ntohl(this->ip_handover_address_);
      endpoint.lease_id = this->ip_handover_.nonce();
    } else if (this->dhcp_probe_pending_ && this->dhcp_quiet_.quiet()) {
      // A reset client may have received its previous DHCP address again.
      // Retire old grants at every LAN edge before ARP conflict detection;
      // an authorized secondary proxy must not look like an address thief.
      endpoint.mode = ::mesh_ip::EndpointMode::QUIET;
      endpoint.address = this->dhcp_client_.lease().address;
      endpoint.lease_id = this->dhcp_quiet_.nonce();
    } else if (direct)
      endpoint.mode = ::mesh_ip::EndpointMode::NATIVE;
    else if (this->dhcp_lease_installed_ && this->dhcp_client_.remaining_seconds(now) != 0) {
      const auto &lease = this->dhcp_client_.lease();
      endpoint.mode = ::mesh_ip::EndpointMode::MESH;
      endpoint.lease_id = this->dhcp_client_.lease_xid();
      endpoint.address = lease.address;
      endpoint.netmask = lease.netmask;
      endpoint.router = lease.router;
      endpoint.server = lease.server;
      endpoint.remaining_seconds = this->dhcp_client_.remaining_seconds(now);
    }
    uint8_t reply[::mesh_ip::ENDPOINT_RESPONSE_SIZE];
    size_t length;
    if (::mesh_ip::encode_endpoint_advertisement(endpoint, reply, sizeof(reply), length) &&
        this->core_->send_control(gateway, ++this->sequence_, reply, length, now))
      this->endpoint_replies_[gateway - 1] = 0;
  }
#ifndef MESH_IP_CLIENT_ONLY
  if (!this->gateway_service_() || !direct)
    return;
  if (uint32_t(now - this->last_endpoint_witness_) >= 1000) {
    this->last_endpoint_witness_ = now;
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
      uint32_t address, xid, remaining;
      if (!this->allowed_(node) || node == this->node_id_ ||
          !this->ip_netif_.local_lease_witness(node, address, xid, remaining))
        continue;
      constexpr auto mode = ::mesh_ip::WitnessIdentityMode::SESSION_BOUND;
      ::mesh_ip::LeaseWitness witness;
      witness.node_id = node;
      witness.address = lwip_ntohl(address);
      witness.lease_id = xid;
      witness.remaining_seconds = remaining;
      witness.subject_session = this->identity_session_(node);
      uint8_t payload[::mesh_ip::SESSION_LEASE_WITNESS_SIZE];
      size_t length;
      if (!::mesh_ip::encode_lease_witness(witness, mode, payload, sizeof(payload), length))
        continue;
      for (uint8_t gateway = 1; gateway <= mesh_limits::MAX_NODES; gateway++)
        if (gateway != this->node_id_ && this->gateway_candidate_(gateway))
          this->core_->send_control(gateway, ++this->sequence_, payload, length, now);
    }
  }
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
    auto &pending = this->pending_endpoint_witness_[node - 1];
    if (!pending.used || uint32_t(now - pending.started) < 2500 || !this->transport_has_room_())
      continue;
    uint8_t request[10]{1, NEED_WITNESS};
    write_be(request + 2, pending.address);
    write_le(request + 6, pending.lease_id);
    if (this->core_->send_control(node, ++this->sequence_, request, sizeof(request), now))
      pending.used = false;
  }
  if (uint32_t(now - this->last_endpoint_challenge_) < 1000)
    return;
  this->last_endpoint_challenge_ = now;
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
    if (!this->allowed_(node) || node == this->node_id_ || !this->transport_has_room_())
      continue;
    const uint64_t nonce = (uint64_t(esp_random()) << 32) | esp_random();
    if (!this->endpoint_challenges_.begin(node, nonce, now))
      continue;
    uint8_t challenge[::mesh_ip::ENDPOINT_CHALLENGE_SIZE];
    size_t length;
    if (!::mesh_ip::encode_endpoint_challenge(nonce, challenge, sizeof(challenge), length) ||
        !this->core_->send_control(node, ++this->sequence_, challenge, length, now))
      this->endpoint_challenges_.cancel(node, nonce);
  }
#endif
}
}  // namespace esphome::mesh
