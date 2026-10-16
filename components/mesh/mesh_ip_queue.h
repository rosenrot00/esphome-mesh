#pragma once

#include "mesh_limits.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mesh_ip {

// Epoch/ownership metadata can travel without a second full packet buffer.
struct QueuedIpMetadata {
  uint32_t generation{0};
  uint32_t peer_epoch{0}, ingress_epoch{0};
  uint8_t destination{0};
  uint8_t ingress_source{0};
  bool gateway_ingress{false};
  uint16_t length{0};
};

struct QueuedIpPacket {
  static constexpr size_t MAX_PACKET_SIZE = 1500;
  uint32_t generation{0};
  uint32_t peer_epoch{0}, ingress_epoch{0};
  uint8_t destination{0};
  uint8_t ingress_source{0};
  bool gateway_ingress{false};
  uint16_t length{0};
  uint8_t data[MAX_PACKET_SIZE]{};
};

// Bounded deficit round robin. No protocol, port number, DSCP or ICMP type
// receives preferential treatment. One greedy flow cannot occupy every slot.
// The platform serializes metadata operations. A reservation gives one writer
// exclusive payload access outside that lock until commit/cancel. Reset never
// reuses an unpublished slot while its writer is still filling it.
class IpFlowQueue {
 public:
  static constexpr size_t CAPACITY = 8;
  static constexpr size_t MAX_PER_FLOW = CAPACITY / 2;
  static constexpr size_t SPARSE_RESERVE = 2;
  static constexpr uint16_t QUANTUM = 512;
  enum class Admission : uint8_t { ACCEPTED, FULL, FLOW_LIMIT };
  struct Reservation {
    uint32_t serial{0};
    uint8_t slot{255};
  };
  struct Key {
    uint32_t source{0}, target{0};
#ifdef MESH_IPV6
    uint32_t source_high[3]{}, target_high[3]{};
    uint8_t family{4};
#endif
    uint16_t source_port{0}, target_port{0};
    uint8_t protocol{0}, destination{0};
    bool operator==(const Key &other) const {
#ifdef MESH_IPV6
      if (family != other.family || std::memcmp(source_high, other.source_high, sizeof(source_high)) != 0 ||
          std::memcmp(target_high, other.target_high, sizeof(target_high)) != 0)
        return false;
#endif
      return source == other.source && target == other.target && source_port == other.source_port &&
             target_port == other.target_port && protocol == other.protocol && destination == other.destination;
    }
  };

  Admission reserve(const Key &key, Reservation &reservation) {
    reservation = {};
    uint8_t flow = NONE, free_flow = NONE, slot = NONE;
    for (uint8_t i = 0; i < CAPACITY; ++i) {
      if (flows_[i].count && flows_[i].key == key)
        flow = i;
      if (!flows_[i].count && free_flow == NONE)
        free_flow = i;
      if (slots_[i].state == State::FREE && slot == NONE)
        slot = i;
    }
    if (flow != NONE &&
        (flows_[flow].count >= MAX_PER_FLOW || (flows_[flow].count >= 2 && occupied_ >= CAPACITY - SPARSE_RESERVE)))
      return Admission::FLOW_LIMIT;
    if (slot == NONE || (flow == NONE && free_flow == NONE))
      return Admission::FULL;
    if (flow == NONE) {
      flow = free_flow;
      flows_[flow] = Flow{};
      flows_[flow].key = key;
    }
    auto &entry = slots_[slot];
    entry.next = NONE;
    entry.flow = flow;
    entry.state = State::RESERVED;
    if (++serial_ == 0)
      ++serial_;
    entry.serial = serial_;
    ++flows_[flow].count;
    ++occupied_;
    reservation.serial = entry.serial;
    reservation.slot = slot;
    return Admission::ACCEPTED;
  }

  QueuedIpPacket *reserved_packet(const Reservation &reservation) {
    return owns_(reservation) ? &slots_[reservation.slot].packet : nullptr;
  }

  bool commit(const Reservation &reservation) {
    if (!owns_(reservation))
      return false;
    auto &entry = slots_[reservation.slot];
    // A reset leaves the writer's storage intact but invalidates its flow.
    if (entry.flow == NONE || entry.packet.length > QueuedIpPacket::MAX_PACKET_SIZE ||
        !(classify(entry.packet) == flows_[entry.flow].key)) {
      cancel(reservation);
      return false;
    }
    auto &queue = flows_[entry.flow];
    entry.state = State::READY;
    if (queue.tail != NONE)
      slots_[queue.tail].next = reservation.slot;
    else
      queue.head = reservation.slot;
    queue.tail = reservation.slot;
    ++size_;
    return true;
  }

  void cancel(const Reservation &reservation) {
    if (!owns_(reservation))
      return;
    auto &entry = slots_[reservation.slot];
    if (entry.flow != NONE && --flows_[entry.flow].count == 0)
      flows_[entry.flow] = Flow{};
    entry.state = State::FREE;
    entry.flow = entry.next = NONE;
    --occupied_;
  }

  Admission push(const QueuedIpPacket &packet) {
    Reservation reservation;
    const auto admitted = reserve(classify(packet), reservation);
    if (admitted != Admission::ACCEPTED)
      return admitted;
    *reserved_packet(reservation) = packet;
    return commit(reservation) ? Admission::ACCEPTED : Admission::FULL;
  }

  bool pop(QueuedIpPacket &packet) {
    QueuedIpMetadata metadata;
    if (!consume(packet.data, sizeof(packet.data), metadata))
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

  // Consume directly into a reserved downstream original. A complete MTU-sized
  // destination is required; failure cannot skip a large head packet or change
  // its DRR deficit. The existing platform queue lock protects this one copy.
  bool consume(uint8_t *target, size_t capacity, QueuedIpMetadata &metadata) {
    if (target == nullptr || capacity < QueuedIpPacket::MAX_PACKET_SIZE)
      return false;
    if (!size_)
      return false;
    // Every packet is <=1500B. Four rounds suffice even from zero deficit.
    for (size_t visit = 0; visit < CAPACITY * 4; ++visit) {
      auto &flow = flows_[cursor_];
      if (flow.head == NONE) {
        advance_();
        continue;
      }
      auto &entry = slots_[flow.head];
      if (flow.deficit < entry.packet.length)
        flow.deficit += QUANTUM;
      if (flow.deficit < entry.packet.length) {
        advance_();
        continue;
      }
      metadata.generation = entry.packet.generation;
      metadata.peer_epoch = entry.packet.peer_epoch;
      metadata.ingress_epoch = entry.packet.ingress_epoch;
      metadata.destination = entry.packet.destination;
      metadata.ingress_source = entry.packet.ingress_source;
      metadata.gateway_ingress = entry.packet.gateway_ingress;
      metadata.length = entry.packet.length;
      std::memcpy(target, entry.packet.data, metadata.length);
      flow.deficit -= metadata.length;
      flow.head = entry.next;
      entry.state = State::FREE;
      entry.flow = entry.next = NONE;
      --flow.count;
      --size_;
      --occupied_;
      if (flow.head == NONE)
        flow.tail = NONE;
      if (!flow.count) {
        flow = Flow{};
        advance_();
      } else if (flow.head == NONE || flow.deficit < slots_[flow.head].packet.length)
        advance_();
      return true;
    }
    return false;
  }

  void reset() {
    occupied_ = 0;
    for (auto &entry : slots_) {
      if (entry.state == State::RESERVED)
        ++occupied_;
      else
        entry.state = State::FREE;
      entry.flow = entry.next = NONE;
    }
    for (auto &flow : flows_)
      flow = Flow{};
    size_ = cursor_ = 0;
  }
  size_t size() const { return size_; }

 private:
  static constexpr uint8_t NONE = 255;
  enum class State : uint8_t { FREE, RESERVED, READY };
  struct Slot {
    QueuedIpPacket packet;
    uint32_t serial{0};
    uint8_t next{NONE}, flow{NONE};
    State state{State::FREE};
  };
  struct Flow {
    Key key;
    uint16_t deficit{0};
    uint8_t head{NONE}, tail{NONE}, count{0};
  };
  static uint16_t be16_(const uint8_t *p) { return uint16_t(p[0]) << 8 | p[1]; }

 public:
  static Key classify(const QueuedIpPacket &packet) { return classify(packet.destination, packet.data, packet.length); }
  // A complete IPv4 header plus four transport bytes (at most 64 bytes) is
  // sufficient; callers need not copy the rest of a pbuf just to admit a flow.
  static Key classify(uint8_t destination, const uint8_t *p, size_t length) {
    Key key;
    key.destination = destination;
    if (p == nullptr || length < 20)
      return key;
#ifdef MESH_IPV6
    key.family = p[0] >> 4;
    if (key.family == 6) {
      if (length < 40)
        return key;
      std::memcpy(&key.source, p + 8, 4);
      std::memcpy(key.source_high, p + 12, 12);
      std::memcpy(&key.target, p + 24, 4);
      std::memcpy(key.target_high, p + 28, 12);
      key.protocol = p[6];
      // The same fixed prefix is classified both before admission and after
      // filling the slot. Long extension chains fall back to exact endpoints;
      // no first/noninitial fragment can manufacture a fresh transport flow.
      const size_t prefix = length < 64 ? length : 64;
      size_t offset = 40;
      uint8_t next = p[6];
      bool fragment = false;
      for (size_t i = 0; i < 6 && (next == 0 || next == 43 || next == 60 || next == 44); ++i) {
        if (offset + 2 > prefix)
          return key;
        const size_t bytes = next == 44 ? 8 : (size_t(p[offset + 1]) + 1) * 8;
        if (bytes > prefix - offset)
          return key;
        fragment |= next == 44;
        next = p[offset];
        offset += bytes;
      }
      if (!fragment && (next == 6 || next == 17) && offset + 4 <= prefix) {
        key.protocol = next;
        key.source_port = be16_(p + offset);
        key.target_port = be16_(p + offset + 2);
      }
      return key;
    }
#endif
    std::memcpy(&key.source, p + 12, 4);
    std::memcpy(&key.target, p + 16, 4);
    key.protocol = p[9];
    const size_t header = (p[0] & 15) * 4;
    // Fragmented traffic uses the endpoint/protocol fallback. A new IPv4 ID
    // must not manufacture a new flow and bypass the bounded flow admission.
    if ((be16_(p + 6) & 0x3fffU) == 0 && (key.protocol == 6 || key.protocol == 17) && header >= 20 &&
        header + 4 <= length) {
      key.source_port = be16_(p + header);
      key.target_port = be16_(p + header + 2);
    }
    return key;
  }

 private:
  bool owns_(const Reservation &reservation) const {
    return reservation.slot < CAPACITY && slots_[reservation.slot].state == State::RESERVED &&
           slots_[reservation.slot].serial == reservation.serial;
  }
  void advance_() { cursor_ = (cursor_ + 1) % CAPACITY; }
  Slot slots_[CAPACITY]{};
  Flow flows_[CAPACITY]{};
  uint32_t serial_{0};
  uint8_t size_{0}, occupied_{0}, cursor_{0};
};

}  // namespace mesh_ip
