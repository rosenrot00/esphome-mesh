#pragma once

#include "mesh_limits.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace mesh_transport {

// Stable mesh identity, not an SDK address. A backend maps it to its native
// addressing scheme. The current identity protocol uses six-byte identities.
using PeerAddress = std::array<uint8_t, 6>;
using PeerLinkKey = std::array<uint8_t, 16>;
constexpr size_t MAX_MANAGEMENT_SIZE = 128;
constexpr PeerAddress MANAGEMENT_FLOOD{{255, 255, 255, 255, 255, 255}};

struct ManagementPacket {
  PeerAddress source{};
  uint16_t length{0};
  uint8_t data[MAX_MANAGEMENT_SIZE]{};
};

// The adapter owns these static-lifetime KDF labels. Distinct link security
// schemes must use distinct labels; membership authentication is independent.
struct LinkKeyContext {
  const char *network{nullptr};
  const char *session{nullptr};
};

struct ManagementTransport {
  void *context{nullptr};
  size_t wire_mtu{0};
  LinkKeyContext key_context{};
  bool (*ready)(const void *){nullptr};
  bool (*send)(void *, const PeerAddress &, const uint8_t *, size_t, uint32_t){nullptr};
  bool (*receive)(void *, ManagementPacket &){nullptr};
  bool (*configure_key)(void *, const PeerLinkKey &){nullptr};
  bool (*install_peer)(void *, uint8_t, const PeerAddress &, const PeerLinkKey &){nullptr};
  bool (*remove_peer)(void *, uint8_t){nullptr};
  bool (*peer_address)(const void *, uint8_t, PeerAddress &){nullptr};
};

// Serialized control-plane boundary. Acceptance means a full bounded copy,
// never delivery. Frames remain untrusted until authentication has verified
// their sender, boot and compatibility. No SDK, allocator, IP or RTOS types.
class ManagementChannel {
 public:
  bool bind(const ManagementTransport &transport, size_t required_wire_size) {
    if (this->bound_ || required_wire_size == 0 || required_wire_size > MAX_MANAGEMENT_SIZE ||
        transport.wire_mtu < required_wire_size || transport.key_context.network == nullptr ||
        transport.key_context.session == nullptr || transport.key_context.network[0] == '\0' ||
        transport.key_context.session[0] == '\0' || transport.ready == nullptr || transport.send == nullptr ||
        transport.receive == nullptr || transport.configure_key == nullptr || transport.install_peer == nullptr ||
        transport.remove_peer == nullptr || transport.peer_address == nullptr)
      return false;
    this->transport_ = transport;
    this->bound_ = true;
    return true;
  }
  bool ready() const { return this->bound_ && this->transport_.ready(this->transport_.context); }
  const LinkKeyContext &key_context() const { return this->transport_.key_context; }
  bool configure_key(const PeerLinkKey &key) {
    return this->bound_ && this->transport_.configure_key(this->transport_.context, key);
  }
  bool send(const PeerAddress &destination, const uint8_t *data, size_t length, uint32_t now) {
    return this->ready() && data != nullptr && length != 0 && length <= MAX_MANAGEMENT_SIZE &&
           length <= this->transport_.wire_mtu &&
           this->transport_.send(this->transport_.context, destination, data, length, now);
  }
  bool receive(ManagementPacket &packet) {
    if (!this->ready() || !this->transport_.receive(this->transport_.context, packet))
      return false;
    uint8_t nonzero = 0;
    for (uint8_t byte : packet.source)
      nonzero |= byte;
    return nonzero != 0 && (packet.source[0] & 1U) == 0 && packet.length != 0 && packet.length <= MAX_MANAGEMENT_SIZE &&
           packet.length <= this->transport_.wire_mtu;
  }
  bool install_peer(uint8_t node, const PeerAddress &address, const PeerLinkKey &key) {
    return this->bound_ && node >= 1 && node <= mesh_limits::MAX_NODES &&
           this->transport_.install_peer(this->transport_.context, node, address, key);
  }
  bool remove_peer(uint8_t node) {
    return this->bound_ && node >= 1 && node <= mesh_limits::MAX_NODES &&
           this->transport_.remove_peer(this->transport_.context, node);
  }
  bool peer_address(uint8_t node, PeerAddress &address) const {
    return this->bound_ && node >= 1 && node <= mesh_limits::MAX_NODES &&
           this->transport_.peer_address(this->transport_.context, node, address);
  }

 protected:
  ManagementTransport transport_{};
  bool bound_{false};
};

}  // namespace mesh_transport
