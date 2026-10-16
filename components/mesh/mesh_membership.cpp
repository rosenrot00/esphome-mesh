#include "mesh_membership.h"

#include <algorithm>
#include <cstring>

namespace mesh_membership {
namespace {

constexpr uint8_t kWireVersion = 4;
constexpr uint8_t kTypeBase = 0x20;
constexpr size_t kHopsOffset = 4;

bool nonzero(const uint8_t *value, size_t length) {
  uint8_t aggregate = 0;
  for (size_t i = 0; i < length; ++i)
    aggregate |= value[i];
  return aggregate != 0;
}

bool newer(uint32_t candidate, uint32_t previous) { return static_cast<int32_t>(candidate - previous) > 0; }

bool same_session(const Claim &first, const Claim &second) {
  return first.mac == second.mac && first.boot == second.boot;
}

bool same_owner(const Claim &first, const Claim &second) {
  return same_session(first, second) && first.node_id == second.node_id &&
         mesh_protocol::same(first.protocol, second.protocol);
}

bool preferred(const Claim &candidate, const Claim &previous) {
  const bool candidate_pinned = (candidate.flags & kPinnedId) != 0;
  const bool previous_pinned = (previous.flags & kPinnedId) != 0;
  if (candidate_pinned != previous_pinned)
    return candidate_pinned;
  return std::lexicographical_compare(candidate.mac.begin(), candidate.mac.end(), previous.mac.begin(),
                                      previous.mac.end());
}

bool valid_interval(uint32_t value) { return value != 0 && value < 0x80000000U; }

void write32(uint8_t *output, uint32_t value) {
  for (size_t i = 0; i < 4; ++i)
    output[i] = static_cast<uint8_t>(value >> (i * 8));
}

void write64(uint8_t *output, uint64_t value) {
  for (size_t i = 0; i < 8; ++i)
    output[i] = static_cast<uint8_t>(value >> (i * 8));
}

uint32_t read32(const uint8_t *input) {
  uint32_t value = 0;
  for (size_t i = 0; i < 4; ++i)
    value |= static_cast<uint32_t>(input[i]) << (i * 8);
  return value;
}

uint64_t read64(const uint8_t *input) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i)
    value |= static_cast<uint64_t>(input[i]) << (i * 8);
  return value;
}

NodeId mac_preference(const Mac &mac) {
  uint32_t hash = 2166136261U;
  for (uint8_t byte : mac)
    hash = (hash ^ byte) * 16777619U;
  return static_cast<NodeId>(hash % kMaxNodes + 1);
}

// This fingerprint only bounds flood work. Admission never depends on hash
// collision resistance: ownership still requires the complete claim and a
// fresh nonce proof, and hop count bounds forwarding even after eviction.
uint64_t fingerprint(const uint8_t *input, size_t length) {
  uint64_t hash = 14695981039346656037ULL;
  for (size_t i = 0; i < length; ++i) {
    if (i != kHopsOffset)
      hash = (hash ^ input[i]) * 1099511628211ULL;
  }
  return hash;
}

}  // namespace

bool valid_mac(const Mac &mac) { return (mac[0] & 1U) == 0 && nonzero(mac.data(), mac.size()); }

bool valid_claim(const Claim &claim) {
  return mesh_protocol::valid(claim.protocol) && valid_mac(claim.mac) &&
         nonzero(claim.boot.data(), claim.boot.size()) && claim.node_id <= kMaxNodes &&
         claim.node_id <= claim.protocol.max_nodes && (claim.flags & ~kKnownFlags) == 0 &&
         ((claim.flags & kNativeUplink) == 0 || (claim.flags & kGatewayCapable) != 0);
}

bool encode_message(const Message &message, uint8_t *output, size_t capacity, size_t &written) {
  written = 0;
  if (output == nullptr || !valid_claim(message.claim) || message.hops == 0 || message.hops > kMaxFloodHops)
    return false;
  size_t length = kClaimWireSize;
  if (message.type != MessageType::CLAIM) {
    if ((message.type != MessageType::CHALLENGE && message.type != MessageType::PROOF) ||
        !valid_mac(message.requester) || message.challenge == 0)
      return false;
    length = kProofWireSize;
  }
  if (capacity < length)
    return false;
  output[0] = 'M';
  output[1] = 'A';
  output[2] = kWireVersion;
  output[3] = kTypeBase + static_cast<uint8_t>(message.type);
  output[4] = message.hops;
  output[5] = message.claim.node_id;
  output[6] = message.claim.flags;
  std::copy(message.claim.mac.begin(), message.claim.mac.end(), output + 7);
  std::copy(message.claim.boot.begin(), message.claim.boot.end(), output + 13);
  write32(output + 29, message.claim.sequence);
  if (!mesh_protocol::encode(message.claim.protocol, output + 33, mesh_protocol::PROFILE_WIRE_SIZE))
    return false;
  if (message.type != MessageType::CLAIM) {
    std::copy(message.requester.begin(), message.requester.end(), output + kClaimWireSize);
    write64(output + kClaimWireSize + 6, message.challenge);
  }
  written = length;
  return true;
}

bool decode_message(const uint8_t *input, size_t length, Message &message) {
  if (input == nullptr || length < kClaimWireSize || input[0] != 'M' || input[1] != 'A' || input[2] != kWireVersion ||
      input[3] <= kTypeBase || input[3] > kTypeBase + static_cast<uint8_t>(MessageType::PROOF))
    return false;
  Message decoded;
  decoded.type = static_cast<MessageType>(input[3] - kTypeBase);
  const size_t expected = decoded.type == MessageType::CLAIM ? kClaimWireSize : kProofWireSize;
  if (length != expected || input[4] == 0 || input[4] > kMaxFloodHops)
    return false;
  decoded.hops = input[4];
  decoded.claim.node_id = input[5];
  decoded.claim.flags = input[6];
  std::copy_n(input + 7, decoded.claim.mac.size(), decoded.claim.mac.begin());
  std::copy_n(input + 13, decoded.claim.boot.size(), decoded.claim.boot.begin());
  decoded.claim.sequence = read32(input + 29);
  if (!mesh_protocol::decode(input + 33, mesh_protocol::PROFILE_WIRE_SIZE, decoded.claim.protocol))
    return false;
  if (!valid_claim(decoded.claim))
    return false;
  if (decoded.type != MessageType::CLAIM) {
    std::copy_n(input + kClaimWireSize, decoded.requester.size(), decoded.requester.begin());
    decoded.challenge = read64(input + kClaimWireSize + 6);
    if (!valid_mac(decoded.requester) || decoded.challenge == 0)
      return false;
  }
  message = decoded;
  return true;
}

bool Membership::begin(const Mac &mac, const BootNonce &boot, NodeId preferred_id, NodeId pinned_id, uint8_t flags,
                       uint32_t now, const mesh_protocol::Profile &protocol) {
  if (initialized_ || protocol.max_nodes != mesh_limits::MAX_NODES || !mesh_protocol::valid(protocol) ||
      !valid_mac(mac) || !nonzero(boot.data(), boot.size()) || preferred_id > kMaxNodes || pinned_id > kMaxNodes ||
      (flags & ~kKnownFlags) != 0 || ((flags & kNativeUplink) != 0 && (flags & kGatewayCapable) == 0) ||
      (pinned_id != 0 && (allowed_ids_ & local_allowed_ids_ & (1U << (pinned_id - 1))) == 0))
    return false;
  pinned_id_ = pinned_id;
  preferred_id_ = preferred_id != 0 ? preferred_id : mac_preference(mac);
  local_.protocol = protocol;
  local_.mac = mac;
  local_.boot = boot;
  local_.flags = static_cast<uint8_t>((flags & ~kPinnedId) | (pinned_id != 0 ? kPinnedId : 0));
  local_.node_id = free_id_();
  local_.sequence = 1;
  initialized_ = true;
  change_slot_(local_.node_id, &local_, now);
  return true;
}

bool Membership::set_allowed_ids(uint16_t mask) {
  if (initialized_ || (mask & ~mesh_limits::ID_MASK) != 0)
    return false;
  allowed_ids_ = mask;
  return true;
}

bool Membership::set_local_allowed_ids(uint16_t mask) {
  if (initialized_ || (mask & ~mesh_limits::ID_MASK) != 0)
    return false;
  local_allowed_ids_ = mask;
  return true;
}

bool Membership::set_timing(const Timing &timing) {
  if (!valid_interval(timing.announce_ms) || !valid_interval(timing.member_lease_ms) ||
      !valid_interval(timing.proof_refresh_ms) || !valid_interval(timing.challenge_retry_ms) ||
      !valid_interval(timing.challenge_timeout_ms) || !valid_interval(timing.flood_dedup_ms) ||
      timing.member_lease_ms <= timing.announce_ms || timing.challenge_timeout_ms <= timing.challenge_retry_ms ||
      timing.flood_dedup_ms >= timing.challenge_retry_ms || timing.proof_refresh_ms >= timing.member_lease_ms ||
      timing.challenge_timeout_ms >= timing.member_lease_ms - timing.proof_refresh_ms)
    return false;
  timing_ = timing;
  return true;
}

const Claim *Membership::find(NodeId node_id) const {
  if (node_id == 0 || node_id > kMaxNodes || !members_[node_id - 1].used)
    return nullptr;
  return &members_[node_id - 1].claim;
}

const Claim *Membership::find(const Mac &mac) const {
  for (const Member &member : members_)
    if (member.used && member.claim.mac == mac)
      return &member.claim;
  return nullptr;
}

uint16_t Membership::member_mask() const {
  uint16_t mask = 0;
  for (size_t i = 0; i < kMaxNodes; ++i)
    if (members_[i].used)
      mask |= static_cast<uint16_t>(1U << i);
  return mask;
}

uint16_t Membership::gateway_mask(bool require_native_uplink) const {
  uint16_t mask = 0;
  for (size_t i = 0; i < kMaxNodes; ++i) {
    const Member &member = members_[i];
    if (member.used && (member.claim.flags & kGatewayCapable) != 0 &&
        (!require_native_uplink || (member.claim.flags & kNativeUplink) != 0))
      mask |= static_cast<uint16_t>(1U << i);
  }
  return mask;
}

bool Membership::send_(const Message &message) {
  uint8_t wire[kMaxWireSize];
  size_t written = 0;
  if (!encode_message(message, wire, sizeof(wire), written) || callbacks_.send == nullptr ||
      !callbacks_.send(callbacks_.context, wire, written)) {
    ++counters_.send_rejected;
    return false;
  }
  return true;
}

void Membership::change_slot_(NodeId slot, const Claim *claim, uint32_t now, bool proved) {
  if (slot == 0 || slot > kMaxNodes)
    return;
  Member &member = members_[slot - 1];
  SlotChange change;
  change.node_id = slot;
  change.had_previous = member.used;
  if (member.used)
    change.previous = member.claim;
  change.has_current = claim != nullptr;
  if (claim != nullptr)
    change.current = *claim;
  const bool identity_change =
      member.used != (claim != nullptr) || (member.used && claim != nullptr && !same_owner(member.claim, *claim));
  if (claim != nullptr) {
    member.used = true;
    member.claim = *claim;
    if (proved || identity_change)
      member.last_proved = now;
  } else {
    member = Member{};
  }
  if (identity_change) {
    ++counters_.owner_changes;
    if (callbacks_.slot_changed != nullptr)
      callbacks_.slot_changed(callbacks_.context, change);
  }
}

NodeId Membership::free_id_() const {
  if (pinned_id_ != 0)
    return (allowed_ids_ & local_allowed_ids_ & (1U << (pinned_id_ - 1))) != 0 && find(pinned_id_) == nullptr
               ? pinned_id_
               : 0;
  for (size_t step = 0; step < kMaxNodes; ++step) {
    const NodeId id = static_cast<NodeId>((preferred_id_ - 1 + step) % kMaxNodes + 1);
    if ((allowed_ids_ & local_allowed_ids_ & (1U << (id - 1))) != 0 && find(id) == nullptr)
      return id;
  }
  return 0;
}

void Membership::move_local_(LocalChange reason, uint32_t now) {
  const NodeId previous = local_.node_id;
  if (previous != 0) {
    const Claim *owner = find(previous);
    if (owner != nullptr && same_session(*owner, local_))
      change_slot_(previous, nullptr, now);
  }
  local_.node_id = reason == LocalChange::PINNED_COLLISION ? 0 : free_id_();
  ++local_.sequence;
  announce_pending_ = true;
  if (local_.node_id != 0)
    change_slot_(local_.node_id, &local_, now);
  else if (previous != 0)
    ++counters_.capacity_exhausted;
  if (previous != local_.node_id && callbacks_.local_changed != nullptr)
    callbacks_.local_changed(callbacks_.context, previous, local_.node_id, reason);
}

bool Membership::commit_(const Claim &claim, uint32_t now) {
  if (!mesh_protocol::compatible(local_.protocol, claim.protocol)) {
    ++counters_.incompatible;
    return false;
  }
  if (claim.node_id == 0 || claim.mac == local_.mac || (allowed_ids_ & (1U << (claim.node_id - 1))) == 0)
    return false;
  const Claim *previous_identity = find(claim.mac);
  if (previous_identity != nullptr && same_session(*previous_identity, claim) &&
      !newer(claim.sequence, previous_identity->sequence)) {
    if (claim.node_id != previous_identity->node_id) {
      ++counters_.replay;
      return false;
    }
    // A new, authenticated direct handshake also counts as proof of life;
    // it cannot roll flags or sequence back to stale handshake metadata.
    members_[claim.node_id - 1].last_proved = now;
    return true;
  }
  const Claim *current = find(claim.node_id);
  if (current != nullptr && current->mac != claim.mac && !preferred(claim, *current))
    return false;
  const NodeId previous_slot = previous_identity != nullptr ? previous_identity->node_id : 0;
  const bool local_loses = current != nullptr && same_session(*current, local_);
  // A verified reboot or compact-ID move retires every outstanding challenge
  // for that MAC. A delayed proof of its previous session/slot cannot undo it.
  for (Pending &pending : pending_)
    if (pending.used && pending.claim.mac == claim.mac)
      pending = Pending{};
  if (previous_slot != 0 && previous_slot != claim.node_id)
    change_slot_(previous_slot, nullptr, now);
  change_slot_(claim.node_id, &claim, now);
  if (local_loses) {
    ++counters_.local_collisions;
    move_local_(pinned_id_ != 0 ? LocalChange::PINNED_COLLISION : LocalChange::COLLISION, now);
  }
  return true;
}

bool Membership::observe_verified(const Claim &claim, uint32_t now) {
  if (initialized_ && !mesh_protocol::compatible(local_.protocol, claim.protocol)) {
    ++counters_.incompatible;
    return false;
  }
  if (!initialized_ || !valid_claim(claim) || claim.node_id == 0 || claim.mac == local_.mac) {
    ++counters_.invalid;
    return false;
  }
  expire_(now);
  // A fresh direct handshake may carry sequence 0 rather than a membership
  // counter. Preserve a later proven record for this same session and slot.
  Claim verified = claim;
  const Claim *previous = find(claim.mac);
  if (previous != nullptr && same_owner(*previous, claim) && !newer(claim.sequence, previous->sequence))
    verified = *previous;
  return commit_(verified, now);
}

void Membership::send_challenge_(Pending &pending, uint32_t now) {
  Message message;
  message.type = MessageType::CHALLENGE;
  message.claim = pending.claim;
  message.requester = local_.mac;
  message.challenge = pending.challenge;
  if (send_(message)) {
    pending.sent = true;
    pending.last_sent = now;
  }
}

bool Membership::start_challenge_(const Claim &claim, uint32_t now) {
  if (claim.node_id == 0 || callbacks_.random_challenge == nullptr || (allowed_ids_ & (1U << (claim.node_id - 1))) == 0)
    return false;
  const Claim *current = find(claim.node_id);
  if (current != nullptr && current->mac != claim.mac && !preferred(claim, *current))
    return false;
  Pending *available = nullptr;
  for (Pending &pending : pending_) {
    if (!pending.used) {
      if (available == nullptr)
        available = &pending;
      continue;
    }
    if (same_session(pending.claim, claim) && pending.claim.node_id == claim.node_id) {
      if (newer(claim.sequence, pending.claim.sequence))
        pending.claim = claim;
      return true;
    }
  }
  if (available == nullptr) {
    ++counters_.pending_full;
    return false;
  }
  const uint64_t challenge = callbacks_.random_challenge(callbacks_.context);
  if (challenge == 0)
    return false;
  *available = Pending{};
  available->used = true;
  available->claim = claim;
  available->minimum_sequence = claim.sequence;
  available->challenge = challenge;
  available->started = now;
  ++counters_.challenges_started;
  send_challenge_(*available, now);
  return true;
}

bool Membership::flood_seen_(const uint8_t *input, size_t length, uint32_t now) {
  const uint64_t value = fingerprint(input, length);
  for (FloodSeen &seen : seen_) {
    if (seen.used && now - seen.last_seen >= timing_.flood_dedup_ms)
      seen.used = false;
    if (seen.used && seen.fingerprint == value)
      return true;
  }
  seen_[seen_cursor_] = {value, now, true};
  seen_cursor_ = (seen_cursor_ + 1) % kFloodCapacity;
  return false;
}

void Membership::receive_claim_(const Claim &claim, uint32_t now) {
  if (claim.mac == local_.mac) {
    // Reflections are normal; another boot using our stable identity is not
    // permitted to replace the running local identity.
    if (claim.boot != local_.boot)
      ++counters_.invalid;
    return;
  }
  const Claim *previous = find(claim.mac);
  if (previous != nullptr && same_session(*previous, claim)) {
    if (!newer(claim.sequence, previous->sequence)) {
      ++counters_.replay;
      return;
    }
    if (claim.node_id == previous->node_id) {
      // A group-authenticated monotonic counter updates metadata, but is not
      // a fresh proof of life: previously unseen buffered claims can replay.
      change_slot_(claim.node_id, &claim, now, false);
      return;
    }
    if (claim.node_id == 0) {
      change_slot_(previous->node_id, nullptr, now);
      return;
    }
  }
  start_challenge_(claim, now);
}

void Membership::receive_challenge_(const Message &message) {
  if (message.claim.mac != local_.mac || message.claim.boot != local_.boot || message.claim.node_id != local_.node_id ||
      local_.node_id == 0 ||
      (message.claim.sequence != local_.sequence && !newer(local_.sequence, message.claim.sequence)))
    return;
  Message proof = message;
  proof.type = MessageType::PROOF;
  proof.hops = kMaxFloodHops;
  proof.claim = local_;
  send_(proof);
}

void Membership::receive_proof_(const Message &message, uint32_t now) {
  if (message.requester != local_.mac)
    return;
  for (Pending &pending : pending_) {
    if (!pending.used || pending.challenge != message.challenge || !same_owner(pending.claim, message.claim) ||
        (pending.minimum_sequence != message.claim.sequence &&
         !newer(message.claim.sequence, pending.minimum_sequence)))
      continue;
    pending.used = false;  // A nonce is accepted at most once.
    ++counters_.proofs_accepted;
    commit_(message.claim, now);
    return;
  }
  ++counters_.replay;
}

bool Membership::receive(const uint8_t *input, size_t length, uint32_t now) {
  Message message;
  if (!initialized_ || !decode_message(input, length, message)) {
    ++counters_.invalid;
    return false;
  }
  if (!mesh_protocol::compatible(local_.protocol, message.claim.protocol)) {
    ++counters_.incompatible;
    return false;
  }
  expire_(now);
  if (flood_seen_(input, length, now)) {
    ++counters_.duplicate;
    return true;
  }
  switch (message.type) {
    case MessageType::CLAIM:
      receive_claim_(message.claim, now);
      break;
    case MessageType::CHALLENGE:
      receive_challenge_(message);
      break;
    case MessageType::PROOF:
      receive_proof_(message, now);
      break;
  }
  if (message.hops > 1) {
    --message.hops;
    send_(message);
  }
  return true;
}

void Membership::expire_(uint32_t now) {
  for (NodeId id = 1; id <= kMaxNodes; ++id) {
    const Member &member = members_[id - 1];
    if (member.used && !same_session(member.claim, local_) && now - member.last_proved >= timing_.member_lease_ms)
      change_slot_(id, nullptr, now);
  }
  for (Pending &pending : pending_)
    if (pending.used && now - pending.started >= timing_.challenge_timeout_ms)
      pending = Pending{};
  if (local_.node_id == 0 && free_id_() != 0)
    move_local_(LocalChange::CAPACITY_AVAILABLE, now);
}

void Membership::tick(uint32_t now) {
  if (!initialized_)
    return;
  expire_(now);
  for (const Member &member : members_)
    if (member.used && !same_session(member.claim, local_) && now - member.last_proved >= timing_.proof_refresh_ms)
      start_challenge_(member.claim, now);
  for (Pending &pending : pending_)
    if (pending.used && (!pending.sent || now - pending.last_sent >= timing_.challenge_retry_ms))
      send_challenge_(pending, now);
  if (!announced_ || announce_pending_ || now - last_announce_ >= timing_.announce_ms) {
    Message announcement;
    announcement.claim = local_;
    ++announcement.claim.sequence;
    if (send_(announcement)) {
      local_ = announcement.claim;
      if (local_.node_id != 0)
        change_slot_(local_.node_id, &local_, now);
      last_announce_ = now;
      announced_ = true;
      announce_pending_ = false;
    }
  }
}

void Membership::set_flags(uint8_t flags) {
  if (!initialized_ || (flags & ~kKnownFlags) != 0 || ((flags & kNativeUplink) != 0 && (flags & kGatewayCapable) == 0))
    return;
  flags = static_cast<uint8_t>((flags & ~kPinnedId) | (pinned_id_ != 0 ? kPinnedId : 0));
  if (flags == local_.flags)
    return;
  local_.flags = flags;
  ++local_.sequence;
  announce_pending_ = true;
  if (local_.node_id != 0) {
    Member &member = members_[local_.node_id - 1];
    if (member.used && same_session(member.claim, local_))
      member.claim = local_;
  }
}

}  // namespace mesh_membership
