#pragma once

#include "mesh_limits.h"

#include "mesh_ip_packet.h"

// Bounded endpoint ARQ above opaque routed frames. This module knows no IP
// protocol/port, radio SDK, RTOS or wall clock. Callers serialize access, send
// each fragment/ACK with a fresh Core sequence, and reset on ownership/session
// or gateway changes. Packet IDs must be unique, monotonically increasing
// modulo 2^32 within one sender session (at most two packets outstanding).
namespace mesh_ip {

constexpr size_t kDeliveryTxSlots = 2;
constexpr size_t kDeliveryWindow = 8;
constexpr size_t kDeliveryAckSize = 24;

struct DeliveryProfile {
  PacketProfile packet{};
  uint32_t retry_interval_ms{250};
  uint32_t packet_lifetime_ms{2000};
  uint8_t max_attempts{5};
  uint32_t max_ack_delay_ms{10};
  uint8_t ack_batch_size{4};
};
bool valid_delivery_profile(const DeliveryProfile &profile);

struct DeliveryCallbacks {
  void *context{nullptr};
  // True means a complete copy was queued. This is not an endpoint ACK.
  bool (*send_fragment)(void *, NodeId, const uint8_t *, size_t){nullptr};
  // ACKs should use the generic CONTROL class; never protocol/port priority.
  bool (*send_ack)(void *, NodeId, const uint8_t *, size_t){nullptr};
  // True transfers complete datagram ownership to a bounded downstream queue.
  // False retains the ready reassembly slot for a later retry.
  bool (*deliver)(void *, NodeId, const uint8_t *, size_t){nullptr};
};

struct DeliveryCounters {
  uint32_t submitted{0}, acknowledged{0}, delivered{0};
  uint32_t fragments_sent{0}, fragment_retries{0}, send_busy{0};
  uint32_t tx_expired{0}, retry_exhausted{0}, receive_busy{0};
  uint32_t acks_sent{0}, ack_busy{0}, invalid_acks{0}, stale_fragments{0};
  uint32_t window_stalls{0};
};

class PacketDelivery {
 public:
  struct TxReservation {
    uint32_t serial{0};
    uint8_t slot{255};
  };
  // Valid reconfiguration aborts packet work, preserving DeliveryCounters.
  // Normally it also clears replay state (a session boundary); false preserves
  // unaffected peers after reset_peer(changed_id). Changing local ID always
  // clears replay history. Invalid configuration leaves state untouched.
  bool configure(NodeId local, const DeliveryProfile &profile, const DeliveryCallbacks &callbacks,
                 bool clear_replay = true);
  bool can_begin() const;
  size_t pending_count() const;
  size_t pending_receive_count() const { return receiver_.pending_packets(); }
  // Forwarded packets name their ingress peer so reset_peer() can abort its
  // retained original. Zero denotes local traffic; the local ID is not an owner.
  bool begin(NodeId destination, const uint8_t *packet, size_t length, uint32_t packet_id, uint32_t now_ms,
             NodeId owner = 0);
  // Reserve either of the existing two originals. Unpublished bytes are never
  // sent. Reset invalidates publication, but retains storage until its writer
  // cancels or attempts commit; an obsolete writer cannot corrupt a new packet.
  bool reserve(TxReservation &reservation);
  uint8_t *reserved_data(const TxReservation &reservation);
  // A matching reservation is consumed on success or failure. Invalid tokens
  // cannot cancel another writer; caller serialization matches begin()/tick().
  bool commit(const TxReservation &reservation, NodeId destination, size_t length, uint32_t packet_id,
              uint32_t now_ms, NodeId owner = 0);
  void cancel(const TxReservation &reservation);
  ReceiveResult receive_fragment(NodeId source, NodeId destination, const uint8_t *fragment, size_t length,
                                 uint32_t now_ms);
  bool accept_ack(NodeId source, const uint8_t *payload, size_t length, uint32_t now_ms);
  void tick(uint32_t now_ms);
  // Aborts state, preserving lifetime counters and configured callbacks.
  // Route-only changes abort work but preserve serial replay history. A new
  // peer boot/identity requires the default full reset or reset_peer().
  void reset(bool clear_replay = true);
  void reset_peer(NodeId peer);
  const DeliveryCounters &counters() const { return counters_; }
  const ReassemblyCounters &reassembly_counters() const { return receiver_.counters(); }
  const DeliveryProfile &profile() const { return profile_; }
  static bool is_ack(const uint8_t *payload, size_t length);

 private:
  struct Tx {
    Fragmenter fragments{};
    uint32_t started_at{0}, last_probe{0};
    uint64_t acknowledged{0}, sent{0};
    uint8_t attempts[kMaxFragmentCount]{};
    // Forwarded originals retain their authenticated ingress owner even after
    // leaving the platform queue. Zero denotes locally originated traffic.
    NodeId destination{0}, owner{0};
    bool used{false}, waiting_commit{false}, window_blocked{false};
    uint32_t reservation_serial{0};
    bool reserved{false}, reservation_valid{false};
  };
  struct Flight {
    uint32_t sent_at{0};
    uint8_t slot{0}, fragment{0};
    bool used{false};
  };
  struct Ack {
    ReassemblyStatus status{};
    uint32_t first_pending{0};
    NodeId destination{0};
    uint8_t new_fragments{0};
    bool used{false}, immediate{false};
  };
  // A bounded serial-number window supplements the ordinary replay cache.
  // Two in-flight packets can commit out of order without duplicate delivery.
  struct Replay {
    uint64_t committed{0};
    uint32_t highest{0};
    bool used{false};
  };
  static constexpr size_t kAckSlots = kReassemblySlots + kDeliveryTxSlots;
  static uint64_t mask_(uint8_t count);
  void release_(size_t slot);
  void queue_ack_(NodeId source, const ReassemblyStatus &status, uint32_t now_ms, bool new_fragment, bool immediate);
  void deliver_ready_(uint32_t now_ms);
  bool replayed_(NodeId source, uint32_t packet_id) const;
  bool outside_window_(NodeId source, uint32_t packet_id) const;
  void remember_(NodeId source, uint32_t packet_id);
  bool transmit_(size_t slot, uint8_t index, uint32_t now_ms, Flight *flight);
  bool within_replay_window_(size_t slot) const;
  bool reservation_matches_(const TxReservation &reservation) const;

  NodeId local_{0};
  DeliveryProfile profile_{};
  DeliveryCallbacks callbacks_{};
  Tx tx_[kDeliveryTxSlots]{};
  Flight flights_[kDeliveryWindow]{};
  Reassembler receiver_{};
  Ack acks_[kAckSlots]{};
  Replay replay_[mesh_core::kMaxNodes]{};
  size_t tx_cursor_{0}, ack_cursor_{0}, rx_cursor_{0};
  DeliveryCounters counters_{};
  bool configured_{false};
  uint32_t reservation_serial_{0};
};

}  // namespace mesh_ip
