#pragma once

#include "mesh_limits.h"

#include "mesh_core.h"
#include "mesh_ip_role.h"

#include <cstddef>
#include <cstdint>

// Portable packet transport only. The adapter validates the enclosed IP packet,
// authenticates peers and gives every emitted fragment its own MeshCore sequence.
// Instances are single-threaded: callers must serialize all access.
namespace mesh_ip {

using NodeId = mesh_core::NodeId;
// Accept ordinary Ethernet-sized IP packets, including TCP connections that
// were established before a transport change. A netif may advertise a lower MTU.
constexpr size_t kMtu = 1500;
constexpr size_t kPacketMtu = kMtu;
constexpr size_t kFragmentHeaderSize = 18;
constexpr size_t kFragmentDataSize = mesh_core::kMaxPayload - kFragmentHeaderSize;
// Legacy/default packet count remains useful to callers sizing ESP-NOW tests.
constexpr size_t kMaxFragments = (kMtu + kFragmentDataSize - 1) / kFragmentDataSize;
constexpr size_t kMaxFragmentCount = 64;
constexpr size_t kMinimumFragmentDataSize = (kMtu + kMaxFragmentCount - 1) / kMaxFragmentCount;
constexpr size_t kMinimumPayloadMtu = kFragmentHeaderSize + kMinimumFragmentDataSize;
#ifdef MESH_IP_CLIENT_ONLY
constexpr size_t kReassemblySlots = 2;  // Existing per-source bound; source is the gateway.
#else
constexpr size_t kReassemblySlots = 8;
#endif
constexpr size_t kMaxSlotsPerSource = 2;
constexpr size_t kReplaySlots = 64;
constexpr uint32_t kReassemblyTimeoutMs = 2000;

struct PacketProfile {
  // Complete mesh payload budget, including the 18-byte v3 fragment header.
  size_t payload_mtu{mesh_core::kMaxPayload};
  uint32_t reassembly_timeout_ms{kReassemblyTimeoutMs};
};
constexpr bool valid_packet_profile(const PacketProfile &profile) {
  return profile.payload_mtu >= kMinimumPayloadMtu && profile.payload_mtu <= mesh_core::kMaxPayload &&
         profile.reassembly_timeout_ms != 0 && profile.reassembly_timeout_ms < 0x80000000U;
}

// A native radio may have a larger frame budget; the portable wire/buffers
// remain bounded by kMaxPayload instead of expanding implicitly.
constexpr PacketProfile packet_profile_for_link(const mesh_transport::LinkCapabilities &link,
                                                uint32_t timeout_ms = kReassemblyTimeoutMs) {
  return PacketProfile{link.payload_mtu < mesh_core::kMaxPayload ? link.payload_mtu : mesh_core::kMaxPayload,
                       timeout_ms};
}

// CRC detects corruption and accidentally mixed fragments; it is not a MAC.
uint32_t packet_crc32(const uint8_t *data, size_t length);

// Version3 header: 'M','I',version=3,flags=0,id LE32,total_length LE16,
// fragment_index U8,fragment_count U8,whole_packet_crc32 LE32,stride LE16.
// Explicit wide stride supports native v2 frames without wrapping at 255.
// Old v1/v2 fragments are rejected; the authenticated common protocol profile
// requires v3 on every member. IP packets and the fragment count remain bounded.
class Fragmenter {
 public:
  // Changes are rejected while a packet is active; failure preserves settings.
  bool set_profile(const PacketProfile &profile);
  const PacketProfile &profile() const { return profile_; }
  // Copies the packet. An active packet cannot be replaced; use reset() to abort.
  bool begin(const uint8_t *packet, size_t length, uint32_t packet_id);
  // The single owner may fill an inactive packet directly, then publish it.
  // Active originals remain immutable until reset(), including ARQ retries.
  uint8_t *writable_packet() { return active_ ? nullptr : packet_; }
  bool begin_in_place(size_t length, uint32_t packet_id);
  // Does not advance. Retry the same fragment when the caller's queue is full.
  bool peek(uint8_t *output, size_t capacity, size_t &written) const;
  // Random access to the retained original for selective repeat; no advancement.
  bool peek_at(uint8_t index, uint8_t *output, size_t capacity, size_t &written) const;
  // Call only after the current fragment was copied into the adapter's queue.
  bool advance();
  void reset();
  bool active() const { return active_; }
  uint8_t fragment_index() const { return index_; }
  uint8_t fragment_count() const { return count_; }
  uint32_t packet_id() const { return packet_id_; }
  size_t packet_length() const { return length_; }
  uint32_t packet_crc() const { return crc_; }

 private:
  PacketProfile profile_{};
  uint8_t packet_[kMtu]{};
  uint32_t packet_id_{0};
  uint32_t crc_{0};
  uint16_t length_{0};
  uint8_t index_{0};
  uint8_t count_{0};
  bool active_{false};
};

enum class ReceiveResult : uint8_t {
  INVALID,
  INCOMPLETE,
  DUPLICATE,
  COMPLETE,
  NO_CAPACITY,
};

struct CompletedPacket {
  // Owned by Reassembler, valid only until its next non-const operation.
  const uint8_t *data{nullptr};
  size_t length{0};
  NodeId source{0};
  NodeId destination{0};
  uint32_t packet_id{0};
};

struct ReassemblyCounters {
  uint32_t accepted_fragments{0};
  uint32_t completed_packets{0};
  uint32_t duplicate_fragments{0};
  uint32_t invalid_fragments{0};
  uint32_t expired_packets{0};
  uint32_t capacity_drops{0};
};

struct ReassemblyStatus {
  uint32_t packet_id{0}, crc{0};
  uint16_t length{0};
  uint8_t count{0};
  uint64_t received_mask{0};
  bool complete{false}, committed{false};
};

class Reassembler {
 public:
  // Changes are rejected while any packet is pending. Reassembly timeout and
  // replay lifetime share this profile; duplicates never extend either.
  bool set_profile(const PacketProfile &profile);
  const PacketProfile &profile() const { return profile_; }
  ReceiveResult receive(NodeId source, NodeId destination, const uint8_t *fragment, size_t length, uint32_t now_ms,
                        CompletedPacket &completed);
  // Transactional path: a complete CRC-checked packet remains held until the
  // endpoint accepts it. No replay entry is committed before commit().
  ReceiveResult receive_deferred(NodeId source, NodeId destination, const uint8_t *fragment, size_t length,
                                 uint32_t now_ms, CompletedPacket &completed);
  bool status(NodeId source, NodeId destination, uint32_t packet_id, ReassemblyStatus &out) const;
  bool completed_at(size_t slot, CompletedPacket &out) const;
  bool commit(NodeId source, NodeId destination, uint32_t packet_id, uint32_t now_ms);
  void discard(NodeId source, NodeId destination, uint32_t packet_id);
  void reset_peer(NodeId peer);
  // Lifetime is measured from the first fragment, never refreshed by duplicates.
  // now_ms is a monotonic wrapping millisecond clock; intervals must be <2^31 ms.
  void expire(uint32_t now_ms);
  void reset();
  size_t pending_packets() const;
  const ReassemblyCounters &counters() const { return counters_; }

 private:
  struct Slot {
    uint64_t received_mask{0};
    uint32_t packet_id{0};
    uint32_t crc{0};
    uint32_t started_at{0};
    uint16_t length{0};
    NodeId source{0};
    NodeId destination{0};
    uint8_t count{0};
    uint16_t fragment_data_size{0};
    bool used{false};
    bool complete{false};
    uint8_t packet[kMtu]{};
  };
  struct Recent {
    uint32_t packet_id{0};
    uint32_t crc{0};
    uint32_t completed_at{0};
    uint16_t length{0};  // Zero denotes an unused replay entry; packets are nonempty.
    NodeId source{0};
    NodeId destination{0};
    uint8_t count{0};
  };

  ReceiveResult receive_(NodeId source, NodeId destination, const uint8_t *fragment, size_t length, uint32_t now_ms,
                         CompletedPacket &completed, bool deferred);

  PacketProfile profile_{};
  Slot slots_[kReassemblySlots]{};
  // A bounded replay cache, not an unbounded guarantee against malicious replay.
  // Completed packet buffers are immediately reusable to avoid throughput limits.
  Recent recent_[kReplaySlots]{};
  size_t recent_cursor_{0};
  ReassemblyCounters counters_{};
};

}  // namespace mesh_ip
