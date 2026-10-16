#pragma once

#include "mesh_protocol.h"

#include <cstddef>
#include <cstdint>

namespace mesh_session {

constexpr size_t WIRE_SIZE = 35;
constexpr uint32_t PROOF_LIFETIME_MS = 2000;
constexpr uint32_t RETRY_INTERVAL_MS = 500;
constexpr uint32_t HELLO_INTERVAL_MS = 1000;
enum class Kind : uint8_t { HELLO = 1, CHALLENGE = 2, RESPONSE = 3 };
struct Message {
  // HELLO is broadcast. CHALLENGE queries a fixed node ID's current boot and
  // canonically has destination_boot=0. RESPONSE binds that requester's boot
  // and nonce to the responder's current nonzero boot; no HELLO is authority.
  Kind kind{Kind::HELLO};
  mesh_protocol::Profile profile{mesh_protocol::manual_profile()};
  uint64_t source_boot{0}, destination_boot{0}, nonce{0};
};
inline bool valid(const Message &message, uint8_t source, uint8_t destination) {
  if (!mesh_limits::valid_node(source) || message.source_boot == 0 ||
      (message.profile.required & mesh_protocol::MANUAL_BOOT_SESSION) == 0 || !mesh_protocol::valid(message.profile) ||
      !mesh_protocol::same(mesh_protocol::manual_profile(), message.profile))
    return false;
  if (message.kind == Kind::HELLO)
    return destination == 0 && message.destination_boot == 0 && message.nonce == 0;
  return mesh_limits::valid_node(destination) && source != destination && message.nonce != 0 &&
         (message.kind == Kind::CHALLENGE ? message.destination_boot == 0
                                          : message.kind == Kind::RESPONSE && message.destination_boot != 0);
}
inline bool encode(const Message &message, uint8_t source, uint8_t destination, uint8_t *output, size_t capacity,
                   size_t &written) {
  written = 0;
  if (output == nullptr || capacity < WIRE_SIZE || !valid(message, source, destination))
    return false;
  output[0] = 1;
  output[1] = static_cast<uint8_t>(message.kind);
  if (!mesh_protocol::encode(message.profile, output + 2, mesh_protocol::PROFILE_WIRE_SIZE))
    return false;
  const uint64_t fields[]{message.source_boot, message.destination_boot, message.nonce};
  for (size_t field = 0; field < 3; ++field)
    for (size_t byte = 0; byte < 8; ++byte)
      output[11 + field * 8 + byte] = static_cast<uint8_t>(fields[field] >> (8 * byte));
  written = WIRE_SIZE;
  return true;
}
inline bool decode(const uint8_t *data, size_t length, uint8_t source, uint8_t destination, Message &message) {
  if (data == nullptr || length != WIRE_SIZE || data[0] != 1)
    return false;
  Message candidate;
  candidate.kind = static_cast<Kind>(data[1]);
  if (!mesh_protocol::decode(data + 2, mesh_protocol::PROFILE_WIRE_SIZE, candidate.profile))
    return false;
  uint64_t *fields[]{&candidate.source_boot, &candidate.destination_boot, &candidate.nonce};
  for (size_t field = 0; field < 3; ++field)
    for (size_t byte = 0; byte < 8; ++byte)
      *fields[field] |= uint64_t(data[11 + field * 8 + byte]) << (8 * byte);
  if (!valid(candidate, source, destination))
    return false;
  message = candidate;
  return true;
}

// The carrier authenticates configured encrypted forwarders. All members of a
// manual mesh therefore retain its existing trusted-forwarder boundary. HELLO
// only offers a candidate: a one-use challenge sent by this boot must be
// answered before a candidate can replace the current session. Serialized.
// random_nonce seeds a peer's first challenge; its uint64 sequence then only
// advances, never wraps. Delayed replies cannot revive after RNG nonce reuse.
class ManualBootSessionRegistry {
 public:
  struct Outgoing {
    uint8_t destination{0};
    Message message{};
  };
  enum class Result : uint8_t { REJECTED, ACCEPTED, CHANGED };
  bool configure(uint8_t own_node, uint64_t own_boot, uint16_t allowed_nodes = mesh_limits::ID_MASK);
  Result receive(uint8_t source, uint8_t destination, const Message &message, uint32_t now, uint64_t random_nonce);
  bool next_outgoing(uint32_t now, Outgoing &outgoing);
  bool sent(const Outgoing &outgoing, uint32_t now);
  uint64_t session(uint8_t node) const;
  uint64_t proved_boot(uint8_t node) const;
  bool activate(uint8_t node, uint64_t proved_boot);

 private:
  struct Peer {
    uint64_t proved{0}, candidate{0}, challenge{0}, last_nonce{0};
    uint64_t reply_boot{0}, reply_nonce{0};
    uint32_t started{0}, last_sent{0}, reply_started{0};
    bool challenge_sent{false}, ready{false};
  };
  bool offer_(Peer &peer, uint64_t boot, uint32_t now, uint64_t nonce);
  uint8_t own_node_{0}, cursor_{0};
  uint16_t allowed_nodes_{0};
  uint64_t own_boot_{0};
  uint32_t last_hello_{0};
  bool hello_sent_{false};
  Peer peers_[mesh_limits::MAX_NODES]{};
};

}  // namespace mesh_session
