#include "mesh_ip_delivery.h"

#include <cstring>

namespace mesh_ip {
namespace {
bool node_valid(NodeId id) { return id >= 1 && id <= mesh_core::kMaxNodes; }
uint16_t read16(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
uint32_t read32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
uint64_t read64(const uint8_t *p) {
  uint64_t result = 0;
  for (size_t i = 0; i < 8; ++i)
    result |= uint64_t(p[i]) << (8 * i);
  return result;
}
void write(uint8_t *p, uint64_t value, size_t bytes) {
  for (size_t i = 0; i < bytes; ++i)
    p[i] = uint8_t(value >> (8 * i));
}
bool newer(uint32_t a, uint32_t b) { return a != b && uint32_t(a - b) < 0x80000000U; }
}  // namespace

bool valid_delivery_profile(const DeliveryProfile &profile) {
  return valid_packet_profile(profile.packet) && profile.retry_interval_ms != 0 &&
         profile.retry_interval_ms < profile.packet_lifetime_ms &&
         profile.packet_lifetime_ms <= profile.packet.reassembly_timeout_ms &&
         profile.packet_lifetime_ms < 0x80000000U && profile.max_attempts >= 2 &&
         profile.max_ack_delay_ms < profile.retry_interval_ms && profile.ack_batch_size >= 1 &&
         profile.ack_batch_size <= kDeliveryWindow;
}

bool PacketDelivery::configure(NodeId local, const DeliveryProfile &profile, const DeliveryCallbacks &callbacks,
                               bool clear_replay) {
  if (!node_valid(local) || !valid_delivery_profile(profile) || callbacks.send_fragment == nullptr ||
      callbacks.send_ack == nullptr || callbacks.deliver == nullptr)
    return false;
  // Valid reconfiguration is an explicit session boundary. Invalid requests
  // above leave the current ownership/state/callbacks untouched.
  reset(clear_replay || local != local_);
  if (!receiver_.set_profile(profile.packet))
    return false;
  for (auto &tx : tx_)
    if (!tx.fragments.set_profile(profile.packet))
      return false;
  local_ = local;
  profile_ = profile;
  callbacks_ = callbacks;
  configured_ = true;
  return true;
}

bool PacketDelivery::can_begin() const {
  if (!configured_)
    return false;
  for (const auto &tx : tx_)
    if (!tx.used && !tx.reserved)
      return true;
  return false;
}

size_t PacketDelivery::pending_count() const {
  size_t result = 0;
  for (const auto &tx : tx_)
    result += tx.used;
  return result;
}

bool PacketDelivery::begin(NodeId destination, const uint8_t *packet, size_t length, uint32_t packet_id,
                           uint32_t now_ms, NodeId owner) {
  if (packet == nullptr || length == 0 || length > kMtu)
    return false;
  TxReservation reservation;
  if (!reserve(reservation))
    return false;
  std::memcpy(reserved_data(reservation), packet, length);
  return commit(reservation, destination, length, packet_id, now_ms, owner);
}

bool PacketDelivery::reserve(TxReservation &reservation) {
  if (reservation_matches_(reservation))
    return false;
  reservation = {};
  if (!configured_)
    return false;
  for (size_t slot = 0; slot < kDeliveryTxSlots; ++slot) {
    auto &tx = tx_[slot];
    if (tx.used || tx.reserved)
      continue;
    bool collision;
    do {
      if (++reservation_serial_ == 0)
        ++reservation_serial_;
      collision = false;
      for (const auto &other : tx_)
        collision |= other.reserved && other.reservation_serial == reservation_serial_;
    } while (collision);
    tx.reserved = tx.reservation_valid = true;
    tx.reservation_serial = reservation_serial_;
    reservation = {reservation_serial_, static_cast<uint8_t>(slot)};
    return true;
  }
  return false;
}

bool PacketDelivery::reservation_matches_(const TxReservation &reservation) const {
  return reservation.slot < kDeliveryTxSlots && reservation.serial != 0 && tx_[reservation.slot].reserved &&
         tx_[reservation.slot].reservation_serial == reservation.serial;
}

uint8_t *PacketDelivery::reserved_data(const TxReservation &reservation) {
  return reservation_matches_(reservation) && tx_[reservation.slot].reservation_valid
             ? tx_[reservation.slot].fragments.writable_packet()
             : nullptr;
}

void PacketDelivery::cancel(const TxReservation &reservation) {
  if (!reservation_matches_(reservation))
    return;
  auto &tx = tx_[reservation.slot];
  tx.reserved = tx.reservation_valid = false;
  tx.fragments.reset();
}

bool PacketDelivery::commit(const TxReservation &reservation, NodeId destination, size_t length, uint32_t packet_id,
                            uint32_t now_ms, NodeId owner) {
  if (!reservation_matches_(reservation))
    return false;
  auto &tx = tx_[reservation.slot];
  bool valid = configured_ && tx.reservation_valid && node_valid(destination) && destination != local_ &&
               (owner == 0 || (node_valid(owner) && owner != local_));
  for (const auto &other : tx_)
    if (other.used && other.fragments.packet_id() == packet_id)
      valid = false;
  if (!valid || !tx.fragments.begin_in_place(length, packet_id)) {
    cancel(reservation);
    return false;
  }
  tx.reserved = tx.reservation_valid = false;
  tx.used = true;
  tx.destination = destination;
  tx.owner = owner;
  tx.started_at = tx.last_probe = now_ms;
  tx.acknowledged = tx.sent = 0;
  tx.waiting_commit = tx.window_blocked = false;
  std::memset(tx.attempts, 0, sizeof(tx.attempts));
  ++counters_.submitted;
  return true;
}

uint64_t PacketDelivery::mask_(uint8_t count) { return count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1; }

void PacketDelivery::release_(size_t slot) {
  tx_[slot].used = false;
  tx_[slot].reservation_valid = false;
  tx_[slot].fragments.reset();
  for (auto &flight : flights_)
    if (flight.used && flight.slot == slot)
      flight.used = false;
}

bool PacketDelivery::is_ack(const uint8_t *payload, size_t length) {
  return payload != nullptr && length == kDeliveryAckSize && payload[0] == 'M' && payload[1] == 'J' && payload[2] == 1;
}

bool PacketDelivery::accept_ack(NodeId source, const uint8_t *payload, size_t length, uint32_t now_ms) {
  if (!configured_ || !node_valid(source) || source == local_ || !is_ack(payload, length) || payload[3] > 1 ||
      payload[11] != 0 || payload[10] == 0 || payload[10] > kMaxFragmentCount) {
    ++counters_.invalid_acks;
    return false;
  }
  const uint32_t id = read32(payload + 4), crc = read32(payload + 12);
  const uint16_t total = read16(payload + 8);
  const uint8_t count = payload[10];
  const uint64_t bits = read64(payload + 16), all = mask_(count);
  if ((bits & ~all) != 0 || (payload[3] == 1 && bits != all)) {
    ++counters_.invalid_acks;
    return false;
  }
  for (size_t i = 0; i < kDeliveryTxSlots; ++i) {
    auto &tx = tx_[i];
    if (!tx.used || tx.destination != source || tx.fragments.packet_id() != id)
      continue;
    if (tx.fragments.packet_crc() != crc || tx.fragments.packet_length() != total ||
        tx.fragments.fragment_count() != count || (bits & ~tx.sent) != 0) {
      ++counters_.invalid_acks;
      return false;
    }
    if (uint32_t(now_ms - tx.started_at) >= profile_.packet_lifetime_ms) {
      release_(i);
      ++counters_.tx_expired;
      return false;
    }
    tx.acknowledged |= bits;
    for (auto &flight : flights_)
      if (flight.used && flight.slot == i && (bits & (UINT64_C(1) << flight.fragment)))
        flight.used = false;
    if (payload[3] == 1) {
      release_(i);
      ++counters_.acknowledged;
    } else if (tx.acknowledged == all && !tx.waiting_commit) {
      tx.waiting_commit = true;
      tx.last_probe = now_ms;
    }
    return true;
  }
  ++counters_.invalid_acks;
  return false;
}

bool PacketDelivery::replayed_(NodeId source, uint32_t packet_id) const {
  const auto &entry = replay_[source - 1];
  if (!entry.used || newer(packet_id, entry.highest))
    return false;
  const uint32_t distance = entry.highest - packet_id;
  return distance < 64 && (entry.committed & (UINT64_C(1) << distance)) != 0;
}

bool PacketDelivery::outside_window_(NodeId source, uint32_t packet_id) const {
  const auto &entry = replay_[source - 1];
  return entry.used && !newer(packet_id, entry.highest) && uint32_t(entry.highest - packet_id) >= 64;
}

void PacketDelivery::remember_(NodeId source, uint32_t packet_id) {
  auto &entry = replay_[source - 1];
  if (!entry.used) {
    entry.used = true;
    entry.highest = packet_id;
    entry.committed = 1;
  } else if (newer(packet_id, entry.highest)) {
    const uint32_t distance = packet_id - entry.highest;
    entry.committed = distance >= 64 ? 1 : (entry.committed << distance) | 1;
    entry.highest = packet_id;
  } else {
    const uint32_t distance = entry.highest - packet_id;
    if (distance < 64)
      entry.committed |= UINT64_C(1) << distance;
  }
}

void PacketDelivery::queue_ack_(NodeId source, const ReassemblyStatus &status, uint32_t now_ms, bool new_fragment,
                                bool immediate) {
  Ack *free = nullptr;
  for (auto &ack : acks_) {
    if (ack.used && ack.destination == source && ack.status.packet_id == status.packet_id) {
      // A later status must never downgrade an already pending commit ACK.
      if (!ack.status.committed)
        ack.status = status;
      if (new_fragment && ack.new_fragments < kMaxFragmentCount)
        ++ack.new_fragments;
      ack.immediate |= immediate || status.committed;
      return;
    }
    if (!ack.used && free == nullptr)
      free = &ack;
  }
  // A dropped ACK is recovered by a bounded retransmission/commit probe. Never
  // evict another receiver's packet data or allocate an unbounded ACK queue.
  if (free != nullptr)
    *free = Ack{status, now_ms, source, uint8_t(new_fragment ? 1 : 0), true, immediate || status.committed};
  else
    ++counters_.ack_busy;
}

ReceiveResult PacketDelivery::receive_fragment(NodeId source, NodeId destination, const uint8_t *fragment,
                                               size_t length, uint32_t now_ms) {
  if (!configured_ || !node_valid(source) || source == local_ || destination != local_)
    return ReceiveResult::INVALID;
  CompletedPacket packet;
  // Reassembler validates the canonical header/stride/length before any ACK.
  const auto result = receiver_.receive_deferred(source, destination, fragment, length, now_ms, packet);
  if (result == ReceiveResult::NO_CAPACITY)
    ++counters_.receive_busy;
  if (result == ReceiveResult::INVALID || result == ReceiveResult::NO_CAPACITY)
    return result;
  const uint32_t id = read32(fragment + 4);
  ReassemblyStatus status;
  if (!receiver_.status(source, destination, id, status))
    return result;
  if (status.committed || replayed_(source, id)) {
    // The complete packet may already have left the generic replay cache.
    // Session-bound serial history still forbids duplicate delivery. Incoming
    // metadata is canonical; a sender must never reuse a packet ID in-session.
    status.received_mask = mask_(status.count);
    status.complete = status.committed = true;
    queue_ack_(source, status, now_ms, false, true);
    receiver_.discard(source, destination, id);
    ++counters_.stale_fragments;
    return ReceiveResult::DUPLICATE;
  }
  if (outside_window_(source, id)) {
    // An ID outside the bounded serial window may be old but never committed.
    // Discard without an ACK rather than falsely acknowledge its delivery.
    receiver_.discard(source, destination, id);
    ++counters_.stale_fragments;
    return ReceiveResult::DUPLICATE;
  }
  // A non-prefix bitmap exposes a gap. Receiving a lower fragment while a
  // higher one is present repairs/reorders that gap; both need prompt feedback.
  const uint8_t index = fragment[10];
  const bool gap = (status.received_mask & (status.received_mask + 1)) != 0;
  const bool higher_received = (status.received_mask & ~mask_(uint8_t(index + 1))) != 0;
  queue_ack_(source, status, now_ms, result != ReceiveResult::DUPLICATE,
             result == ReceiveResult::DUPLICATE || status.complete || gap || higher_received);
  return result;
}

void PacketDelivery::deliver_ready_(uint32_t now_ms) {
  for (size_t checked = 0; checked < kReassemblySlots; ++checked) {
    const size_t index = rx_cursor_++ % kReassemblySlots;
    CompletedPacket packet;
    if (!receiver_.completed_at(index, packet))
      continue;
    if (replayed_(packet.source, packet.packet_id)) {
      receiver_.commit(packet.source, packet.destination, packet.packet_id, now_ms);
      continue;
    }
    if (!callbacks_.deliver(callbacks_.context, packet.source, packet.data, packet.length)) {
      ++counters_.receive_busy;
      continue;
    }
    ReassemblyStatus status;
    receiver_.status(packet.source, packet.destination, packet.packet_id, status);
    if (receiver_.commit(packet.source, packet.destination, packet.packet_id, now_ms)) {
      remember_(packet.source, packet.packet_id);
      status.committed = true;
      queue_ack_(packet.source, status, now_ms, false, true);
      ++counters_.delivered;
    }
  }
}

bool PacketDelivery::transmit_(size_t slot, uint8_t index, uint32_t now_ms, Flight *flight) {
  auto &tx = tx_[slot];
  if (tx.attempts[index] >= profile_.max_attempts) {
    release_(slot);
    ++counters_.retry_exhausted;
    return false;
  }
  uint8_t payload[mesh_core::kMaxPayload];
  size_t length = 0;
  if (!tx.fragments.peek_at(index, payload, sizeof(payload), length))
    return false;
  if (!callbacks_.send_fragment(callbacks_.context, tx.destination, payload, length)) {
    ++counters_.send_busy;
    return false;
  }
  if (tx.attempts[index]++ != 0)
    ++counters_.fragment_retries;
  tx.sent |= UINT64_C(1) << index;
  *flight = Flight{now_ms, uint8_t(slot), index, true};
  ++counters_.fragments_sent;
  return true;
}

bool PacketDelivery::within_replay_window_(size_t slot) const {
  const auto &tx = tx_[slot];
  const uint32_t id = tx.fragments.packet_id();
  for (size_t other = 0; other < kDeliveryTxSlots; ++other) {
    const auto &old = tx_[other];
    if (other == slot || !old.used || old.destination != tx.destination)
      continue;
    const uint32_t old_id = old.fragments.packet_id();
    // Keep the receiver's bounded 64-ID serial window behind every still-live
    // packet to this endpoint, even if its first fragment has not arrived yet.
    // The original newer packet is retained; unrelated endpoints stay free.
    if (newer(id, old_id) && uint32_t(id - old_id) >= 64)
      return false;
  }
  return true;
}

void PacketDelivery::tick(uint32_t now_ms) {
  if (!configured_)
    return;
  receiver_.expire(now_ms);
  deliver_ready_(now_ms);
  // Rotate bounded pending ACKs independently of data admission.
  for (size_t checked = 0; checked < kAckSlots; ++checked) {
    auto &ack = acks_[ack_cursor_++ % kAckSlots];
    if (!ack.used)
      continue;
    const uint32_t elapsed = now_ms - ack.first_pending;
    if (!ack.immediate && ack.new_fragments < profile_.ack_batch_size &&
        !(elapsed < 0x80000000U && elapsed >= profile_.max_ack_delay_ms))
      continue;
    const auto &status = ack.status;
    uint8_t payload[kDeliveryAckSize]{'M', 'J', 1, uint8_t(status.committed ? 1 : 0)};
    write(payload + 4, status.packet_id, 4);
    write(payload + 8, status.length, 2);
    payload[10] = status.count;
    write(payload + 12, status.crc, 4);
    write(payload + 16, status.received_mask, 8);
    if (callbacks_.send_ack(callbacks_.context, ack.destination, payload, sizeof(payload))) {
      ack.used = false;
      ++counters_.acks_sent;
    } else
      ++counters_.ack_busy;
  }
  for (size_t slot = 0; slot < kDeliveryTxSlots; ++slot) {
    if (tx_[slot].used && uint32_t(now_ms - tx_[slot].started_at) >= profile_.packet_lifetime_ms) {
      release_(slot);
      ++counters_.tx_expired;
    }
  }
  // At most the fixed global window is admitted per service pass. A slot gets
  // one attempt before its peer slot, including retransmissions.
  for (size_t budget = 0; budget < kDeliveryWindow; ++budget) {
    bool attempted = false, accepted = false;
    for (size_t checked = 0; checked < kDeliveryTxSlots; ++checked) {
      const size_t slot = tx_cursor_++ % kDeliveryTxSlots;
      auto &tx = tx_[slot];
      if (!tx.used)
        continue;
      if (!within_replay_window_(slot)) {
        if (!tx.window_blocked)
          ++counters_.window_stalls;
        tx.window_blocked = true;
        continue;
      }
      tx.window_blocked = false;
      Flight *free = nullptr, *retry = nullptr;
      for (auto &flight : flights_) {
        if (!flight.used) {
          if (free == nullptr)
            free = &flight;
        } else if (flight.slot == slot && uint32_t(now_ms - flight.sent_at) >= profile_.retry_interval_ms &&
                   retry == nullptr)
          retry = &flight;
      }
      if (retry != nullptr) {
        attempted = true;
        accepted = transmit_(slot, retry->fragment, now_ms, retry);
      } else if (free != nullptr) {
        if (tx.waiting_commit) {
          if (uint32_t(now_ms - tx.last_probe) < profile_.retry_interval_ms)
            continue;
          attempted = true;
          accepted = transmit_(slot, uint8_t(tx.fragments.fragment_count() - 1), now_ms, free);
          if (accepted)
            tx.last_probe = now_ms;
        } else {
          uint8_t index = 0;
          for (; index < tx.fragments.fragment_count(); ++index)
            if ((tx.sent & (UINT64_C(1) << index)) == 0)
              break;
          if (index == tx.fragments.fragment_count())
            continue;
          attempted = true;
          accepted = transmit_(slot, index, now_ms, free);
        }
      }
      if (attempted)
        break;
    }
    if (!attempted || !accepted)
      break;
  }
}

void PacketDelivery::reset(bool clear_replay) {
  for (size_t slot = 0; slot < kDeliveryTxSlots; ++slot)
    release_(slot);
  receiver_.reset();
  for (auto &ack : acks_)
    ack.used = false;
  if (clear_replay)
    for (auto &entry : replay_)
      entry.used = false;
  tx_cursor_ = ack_cursor_ = rx_cursor_ = 0;
}

void PacketDelivery::reset_peer(NodeId peer) {
  if (!node_valid(peer))
    return;
  for (size_t slot = 0; slot < kDeliveryTxSlots; ++slot) {
    // A filling reservation has not declared its destination/ingress owner yet.
    // Keep its storage, but require the caller to obtain a fresh epoch snapshot.
    tx_[slot].reservation_valid = false;
    if (tx_[slot].used && (tx_[slot].destination == peer || tx_[slot].owner == peer))
      release_(slot);
  }
  receiver_.reset_peer(peer);
  for (auto &ack : acks_)
    if (ack.destination == peer)
      ack.used = false;
  replay_[peer - 1] = {};
}

}  // namespace mesh_ip
