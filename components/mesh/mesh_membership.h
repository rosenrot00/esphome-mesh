#pragma once

#include "mesh_limits.h"

#include "mesh_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>

// Identity and admission are independent of the routing core's compact IDs.
// This module contains no cryptography: the platform authenticates the outer
// management message and its immediate peer before calling receive(). All
// holders of the mesh credential are one trust group, not separate principals.
namespace mesh_membership {

using Mac = std::array<uint8_t, 6>;
using BootNonce = std::array<uint8_t, 16>;
using NodeId = uint8_t;
constexpr NodeId kMaxNodes = mesh_limits::MAX_NODES;
constexpr uint8_t kMaxFloodHops = 8;
constexpr uint8_t kGatewayCapable = 1U << 0;
constexpr uint8_t kPinnedId = 1U << 1;
constexpr uint8_t kNativeUplink = 1U << 2;
constexpr uint8_t kKnownFlags = kGatewayCapable | kPinnedId | kNativeUplink;
constexpr size_t kClaimWireSize = 33 + mesh_protocol::PROFILE_WIRE_SIZE;
constexpr size_t kProofWireSize = 47 + mesh_protocol::PROFILE_WIRE_SIZE;
constexpr size_t kMaxWireSize = kProofWireSize;

struct Claim {
  Mac mac{};
  BootNonce boot{};
  NodeId node_id{0};
  uint8_t flags{0};
  uint32_t sequence{0};
  mesh_protocol::Profile protocol{};
};

enum class MessageType : uint8_t { CLAIM = 1, CHALLENGE = 2, PROOF = 3 };
struct Message {
  MessageType type{MessageType::CLAIM};
  uint8_t hops{kMaxFloodHops};
  Claim claim{};
  Mac requester{};
  uint64_t challenge{0};
};

struct Timing {
  uint32_t announce_ms{1000};
  uint32_t member_lease_ms{12000};
  uint32_t proof_refresh_ms{5000};
  uint32_t challenge_retry_ms{750};
  uint32_t challenge_timeout_ms{4000};
  uint32_t flood_dedup_ms{500};
};

enum class LocalChange : uint8_t {
  COLLISION = 1,
  PINNED_COLLISION = 2,
  CAPACITY_AVAILABLE = 3,
};

struct SlotChange {
  NodeId node_id{0};
  bool had_previous{false};
  Claim previous{};
  bool has_current{false};
  Claim current{};
};

struct Counters {
  uint32_t invalid{0};
  uint32_t incompatible{0};
  uint32_t duplicate{0};
  uint32_t replay{0};
  uint32_t challenges_started{0};
  uint32_t proofs_accepted{0};
  uint32_t owner_changes{0};
  uint32_t local_collisions{0};
  uint32_t pending_full{0};
  uint32_t capacity_exhausted{0};
  uint32_t send_rejected{0};
};

// Each send is one identity-addressed management flood, separate from the
// core's ID routing. It must copy atomically; false permits later retry. The
// outer adapter signs it with the group-management key and fans out only to
// authenticated immediate peers. Forwarded packets retain their signed body
// except for the decremented hops; the adapter signs the new outer message.
// Callbacks may record work but must not synchronously re-enter this registry.
struct Callbacks {
  void *context{nullptr};
  bool (*send)(void *, const uint8_t *, size_t){nullptr};
  // Supply an unpredictable, nonzero nonce for every new challenge. Never use
  // a constant/counter seeded identically across boots. Null disables remote
  // claims, but observe_verified() still accepts fresh direct-peer proofs.
  uint64_t (*random_challenge)(void *){nullptr};
  // On every slot identity/session change, discard old Core/IP/DHCP/discovery
  // ownership before allowing the new owner to use that compact ID. Metadata
  // refreshes for the same owner do not call slot_changed.
  void (*slot_changed)(void *, const SlotChange &){nullptr};
  void (*local_changed)(void *, NodeId, NodeId, LocalChange){nullptr};
};

bool valid_mac(const Mac &mac);
bool valid_claim(const Claim &claim);
bool encode_message(const Message &message, uint8_t *output, size_t capacity, size_t &written);
bool decode_message(const uint8_t *input, size_t length, Message &message);

class Membership {
 public:
  // preferred_id is an optional persisted auto ID; pinned_id is an optional
  // administrator constraint. Both are 0 or 1..16. An unassigned local node
  // uses ID 0 only in management; it must not start a Core/IP endpoint.
  bool begin(const Mac &mac, const BootNonce &boot, NodeId preferred_id = 0, NodeId pinned_id = 0,
             uint8_t flags = kGatewayCapable, uint32_t now = 0, const mesh_protocol::Profile &protocol = {});
  void set_callbacks(const Callbacks &callbacks) { callbacks_ = callbacks; }
  // Optional manual compact-ID restriction. Call before begin(); the default
  // permits all 16 slots. Zero permits management only, with no local slot.
  bool set_allowed_ids(uint16_t mask);
  // Separately reserve slots for other MAC identities. This constrains only
  // our allocator; authenticated remote owners still use allowed_ids.
  bool set_local_allowed_ids(uint16_t mask);
  bool set_timing(const Timing &timing);
  const Timing &timing() const { return timing_; }
  void tick(uint32_t now);
  // Authenticated physical neighbor handshake has proven this exact MAC,
  // boot and slot freshly. A HELLO/unencrypted discovery is not this proof.
  // sequence 0 may seed a freshly authenticated peer; a repeat cannot roll
  // back a later authenticated membership announcement's sequence/flags.
  bool observe_verified(const Claim &claim, uint32_t now);
  // The caller verifies group HMAC and current immediate-peer session first.
  // CLAIM alone never changes a different identity/session's live slot. A
  // fresh local nonce proof is required, even for relayed group-auth packets.
  // Metadata announcements never extend the hard proof lease. Direct fresh
  // authentication or periodic identity nonce proofs renew it; buffering
  // previously unseen sequence numbers cannot keep an offline owner alive.
  bool receive(const uint8_t *input, size_t length, uint32_t now);
  void set_flags(uint8_t flags);
  void request_announce() { announce_pending_ = true; }

  const Claim &local_claim() const { return local_; }
  NodeId local_id() const { return local_.node_id; }
  bool initialized() const { return initialized_; }
  bool capacity_waiting() const { return initialized_ && local_.node_id == 0; }
  const Claim *find(NodeId node_id) const;
  const Claim *find(const Mac &mac) const;
  uint16_t member_mask() const;
  uint16_t gateway_mask(bool require_native_uplink = false) const;
  const Counters &counters() const { return counters_; }

 private:
  struct Member {
    bool used{false};
    Claim claim{};
    uint32_t last_proved{0};
  };
  struct Pending {
    bool used{false};
    Claim claim{};
    uint64_t challenge{0};
    uint32_t started{0}, last_sent{0};
    uint32_t minimum_sequence{0};
    bool sent{false};
  };
  struct FloodSeen {
    uint64_t fingerprint{0};
    uint32_t last_seen{0};
    bool used{false};
  };
  static constexpr size_t kPendingCapacity = kMaxNodes;
  static constexpr size_t kFloodCapacity = 64;

  bool send_(const Message &message);
  bool commit_(const Claim &claim, uint32_t now);
  bool start_challenge_(const Claim &claim, uint32_t now);
  void send_challenge_(Pending &pending, uint32_t now);
  void expire_(uint32_t now);
  void change_slot_(NodeId slot, const Claim *claim, uint32_t now, bool proved = true);
  void move_local_(LocalChange reason, uint32_t now);
  NodeId free_id_() const;
  bool flood_seen_(const uint8_t *input, size_t length, uint32_t now);
  void receive_claim_(const Claim &claim, uint32_t now);
  void receive_challenge_(const Message &message);
  void receive_proof_(const Message &message, uint32_t now);

  Claim local_{};
  NodeId pinned_id_{0}, preferred_id_{0};
  uint16_t allowed_ids_{mesh_limits::ID_MASK};
  uint16_t local_allowed_ids_{mesh_limits::ID_MASK};
  bool initialized_{false}, announce_pending_{true}, announced_{false};
  uint32_t last_announce_{0};
  Callbacks callbacks_{};
  Timing timing_{};
  Member members_[kMaxNodes]{};
  Pending pending_[kPendingCapacity]{};
  FloodSeen seen_[kFloodCapacity]{};
  size_t seen_cursor_{0};
  Counters counters_{};
};

}  // namespace mesh_membership
