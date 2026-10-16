#include "mesh_ip_packet.h"

#include <algorithm>
#include <cstring>

namespace mesh_ip {
namespace {

static_assert(kFragmentDataSize > 0, "Fragment header must fit core payload");
static_assert(kMaxFragmentCount <= 64, "Reassembly mask is 64 bits");
static_assert(kMinimumFragmentDataSize > 0, "Fragment stride must remain positive");
static_assert(kMtu <= UINT16_MAX, "Wire packet length is 16 bits");
static_assert(kFragmentDataSize <= UINT16_MAX, "Wire fragment stride is 16 bits");

uint16_t read16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) | static_cast<uint16_t>(static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

void write16(uint8_t *p, uint16_t value) {
  p[0] = static_cast<uint8_t>(value);
  p[1] = static_cast<uint8_t>(value >> 8);
}

void write32(uint8_t *p, uint32_t value) {
  p[0] = static_cast<uint8_t>(value);
  p[1] = static_cast<uint8_t>(value >> 8);
  p[2] = static_cast<uint8_t>(value >> 16);
  p[3] = static_cast<uint8_t>(value >> 24);
}

bool valid_node(NodeId node) { return node >= 1 && node <= mesh_core::kMaxNodes; }

}  // namespace

uint32_t packet_crc32(const uint8_t *data, size_t length) {
  uint32_t crc = UINT32_MAX;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; ++bit)
      crc = (crc >> 1) ^ ((0U - (crc & 1U)) & 0xedb88320U);
  }
  return crc ^ UINT32_MAX;
}

bool Fragmenter::set_profile(const PacketProfile &profile) {
  if (active_ || !valid_packet_profile(profile))
    return false;
  profile_ = profile;
  return true;
}

bool Fragmenter::begin(const uint8_t *packet, size_t length, uint32_t packet_id) {
  if (active_ || packet == nullptr || length == 0 || length > kMtu)
    return false;
  std::memcpy(packet_, packet, length);
  return begin_in_place(length, packet_id);
}

bool Fragmenter::begin_in_place(size_t length, uint32_t packet_id) {
  if (active_ || length == 0 || length > kMtu)
    return false;
  packet_id_ = packet_id;
  length_ = static_cast<uint16_t>(length);
  crc_ = packet_crc32(packet_, length);
  index_ = 0;
  const size_t data_size = profile_.payload_mtu - kFragmentHeaderSize;
  count_ = static_cast<uint8_t>((length + data_size - 1) / data_size);
  active_ = true;
  return true;
}

bool Fragmenter::peek(uint8_t *output, size_t capacity, size_t &written) const {
  return peek_at(index_, output, capacity, written);
}

bool Fragmenter::peek_at(uint8_t index, uint8_t *output, size_t capacity, size_t &written) const {
  written = 0;
  if (!active_ || index >= count_ || output == nullptr)
    return false;
  const size_t data_size = profile_.payload_mtu - kFragmentHeaderSize;
  const size_t offset = static_cast<size_t>(index) * data_size;
  const size_t chunk = std::min(data_size, length_ - offset);
  if (capacity < kFragmentHeaderSize + chunk)
    return false;
  output[0] = 'M';
  output[1] = 'I';
  output[2] = 3;
  output[3] = 0;
  write32(output + 4, packet_id_);
  write16(output + 8, length_);
  output[10] = index;
  output[11] = count_;
  write32(output + 12, crc_);
  write16(output + 16, static_cast<uint16_t>(data_size));
  std::memcpy(output + kFragmentHeaderSize, packet_ + offset, chunk);
  written = kFragmentHeaderSize + chunk;
  return true;
}

bool Fragmenter::advance() {
  if (!active_)
    return false;
  ++index_;
  if (index_ == count_)
    active_ = false;
  return true;
}

void Fragmenter::reset() {
  active_ = false;
  length_ = 0;
  index_ = 0;
  count_ = 0;
}

bool Reassembler::set_profile(const PacketProfile &profile) {
  if (pending_packets() != 0 || !valid_packet_profile(profile))
    return false;
  profile_ = profile;
  // Do not preserve replay entries across a lifetime-profile change.
  for (auto &entry : recent_)
    entry.length = 0;
  recent_cursor_ = 0;
  return true;
}

void Reassembler::expire(uint32_t now_ms) {
  for (auto &slot : slots_) {
    if (slot.used && now_ms - slot.started_at >= profile_.reassembly_timeout_ms) {
      slot.used = false;
      ++counters_.expired_packets;
    }
  }
  for (auto &entry : recent_) {
    if (entry.length != 0 && now_ms - entry.completed_at >= profile_.reassembly_timeout_ms)
      entry.length = 0;
  }
}

void Reassembler::reset() {
  for (auto &slot : slots_)
    slot.used = false;
  for (auto &entry : recent_)
    entry.length = 0;
  recent_cursor_ = 0;
  counters_ = ReassemblyCounters{};
}

size_t Reassembler::pending_packets() const {
  size_t count = 0;
  for (const auto &slot : slots_)
    count += slot.used;
  return count;
}

ReceiveResult Reassembler::receive(NodeId source, NodeId destination, const uint8_t *fragment, size_t length,
                                   uint32_t now_ms, CompletedPacket &completed) {
  return receive_(source, destination, fragment, length, now_ms, completed, false);
}

ReceiveResult Reassembler::receive_deferred(NodeId source, NodeId destination, const uint8_t *fragment, size_t length,
                                            uint32_t now_ms, CompletedPacket &completed) {
  return receive_(source, destination, fragment, length, now_ms, completed, true);
}

bool Reassembler::status(NodeId source, NodeId destination, uint32_t packet_id, ReassemblyStatus &out) const {
  out = {};
  for (const auto &slot : slots_) {
    if (slot.used && slot.source == source && slot.destination == destination && slot.packet_id == packet_id) {
      out = {slot.packet_id, slot.crc, slot.length, slot.count, slot.received_mask, slot.complete, false};
      return true;
    }
  }
  for (const auto &entry : recent_) {
    if (entry.length != 0 && entry.source == source && entry.destination == destination &&
        entry.packet_id == packet_id) {
      const uint64_t mask = entry.count == 64 ? UINT64_MAX : (UINT64_C(1) << entry.count) - 1;
      out = {entry.packet_id, entry.crc, entry.length, entry.count, mask, true, true};
      return true;
    }
  }
  return false;
}

bool Reassembler::completed_at(size_t index, CompletedPacket &out) const {
  out = {};
  if (index >= kReassemblySlots || !slots_[index].used || !slots_[index].complete)
    return false;
  const auto &slot = slots_[index];
  out = {slot.packet, slot.length, slot.source, slot.destination, slot.packet_id};
  return true;
}

bool Reassembler::commit(NodeId source, NodeId destination, uint32_t packet_id, uint32_t now_ms) {
  for (auto &slot : slots_) {
    if (!slot.used || !slot.complete || slot.source != source || slot.destination != destination ||
        slot.packet_id != packet_id)
      continue;
    recent_[recent_cursor_] =
        Recent{slot.packet_id, slot.crc, now_ms, slot.length, slot.source, slot.destination, slot.count};
    recent_cursor_ = (recent_cursor_ + 1) % kReplaySlots;
    slot.used = false;
    return true;
  }
  return false;
}

void Reassembler::discard(NodeId source, NodeId destination, uint32_t packet_id) {
  for (auto &slot : slots_)
    if (slot.used && slot.source == source && slot.destination == destination && slot.packet_id == packet_id)
      slot.used = false;
}

void Reassembler::reset_peer(NodeId peer) {
  for (auto &slot : slots_)
    if (slot.source == peer || slot.destination == peer)
      slot.used = false;
  for (auto &entry : recent_)
    if (entry.source == peer || entry.destination == peer)
      entry.length = 0;
}

ReceiveResult Reassembler::receive_(NodeId source, NodeId destination, const uint8_t *fragment, size_t length,
                                    uint32_t now_ms, CompletedPacket &completed, bool deferred) {
  completed = CompletedPacket{};
  expire(now_ms);
  const auto invalid = [this]() {
    ++counters_.invalid_fragments;
    return ReceiveResult::INVALID;
  };
  if (!valid_node(source) || !valid_node(destination) || fragment == nullptr || length < kFragmentHeaderSize ||
      length > profile_.payload_mtu)
    return invalid();
  if (fragment[0] != 'M' || fragment[1] != 'I')
    return invalid();
  if (fragment[2] != 3 || fragment[3] != 0)
    return invalid();
  const size_t data_size = read16(fragment + 16);
  // A short final fragment does not permit a sender to announce a larger
  // budget than this receiver supports; every packet has one explicit stride.
  if (data_size < kMinimumFragmentDataSize || data_size + kFragmentHeaderSize > profile_.payload_mtu)
    return invalid();
  const uint32_t packet_id = read32(fragment + 4);
  const uint16_t total = read16(fragment + 8);
  const uint8_t index = fragment[10];
  const uint8_t count = fragment[11];
  const uint32_t crc = read32(fragment + 12);
  if (total == 0 || total > kMtu || count == 0 || count > kMaxFragmentCount ||
      count != (total + data_size - 1) / data_size || index >= count)
    return invalid();
  const size_t offset = static_cast<size_t>(index) * data_size;
  const size_t chunk = std::min(data_size, static_cast<size_t>(total) - offset);
  if (length != kFragmentHeaderSize + chunk)
    return invalid();

  for (const auto &entry : recent_) {
    if (entry.length != 0 && entry.source == source && entry.destination == destination &&
        entry.packet_id == packet_id) {
      if (entry.length != total || entry.crc != crc)
        return invalid();
      ++counters_.duplicate_fragments;
      return ReceiveResult::DUPLICATE;
    }
  }

  Slot *slot = nullptr;
  Slot *free_slot = nullptr;
  size_t source_slots = 0;
  for (auto &candidate : slots_) {
    if (!candidate.used) {
      if (free_slot == nullptr)
        free_slot = &candidate;
      continue;
    }
    source_slots += candidate.source == source;
    if (candidate.source == source && candidate.destination == destination && candidate.packet_id == packet_id)
      slot = &candidate;
  }
  if (slot != nullptr) {
    // Reject conflicting metadata without allowing it to evict a valid packet.
    if (slot->length != total || slot->crc != crc || slot->count != count || slot->fragment_data_size != data_size)
      return invalid();
  } else {
    if (free_slot == nullptr || source_slots >= kMaxSlotsPerSource) {
      ++counters_.capacity_drops;
      return ReceiveResult::NO_CAPACITY;
    }
    slot = free_slot;
    slot->used = true;
    slot->complete = false;
    slot->source = source;
    slot->destination = destination;
    slot->packet_id = packet_id;
    slot->crc = crc;
    slot->length = total;
    slot->count = count;
    slot->fragment_data_size = static_cast<uint16_t>(data_size);
    slot->received_mask = 0;
    slot->started_at = now_ms;
  }

  const uint64_t bit = UINT64_C(1) << index;
  if ((slot->received_mask & bit) != 0) {
    if (std::memcmp(slot->packet + offset, fragment + kFragmentHeaderSize, chunk) != 0)
      return invalid();
    ++counters_.duplicate_fragments;
    return ReceiveResult::DUPLICATE;
  }
  std::memcpy(slot->packet + offset, fragment + kFragmentHeaderSize, chunk);
  slot->received_mask |= bit;
  ++counters_.accepted_fragments;
  const uint64_t complete_mask = count == 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1U;
  if (slot->received_mask != complete_mask)
    return ReceiveResult::INCOMPLETE;

  if (packet_crc32(slot->packet, total) != crc) {
    slot->used = false;
    return invalid();
  }
  slot->complete = true;
  completed = CompletedPacket{slot->packet, total, source, destination, packet_id};
  ++counters_.completed_packets;
  if (!deferred)
    commit(source, destination, packet_id, now_ms);
  return ReceiveResult::COMPLETE;
}

}  // namespace mesh_ip
