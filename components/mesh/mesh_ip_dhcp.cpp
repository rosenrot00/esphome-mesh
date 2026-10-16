#include "mesh_ip_dhcp.h"

#include <algorithm>
#include <cstring>

namespace mesh_ip {
namespace {
constexpr uint16_t kType = 1U << 0;
constexpr uint16_t kServer = 1U << 1;
constexpr uint16_t kMask = 1U << 2;
constexpr uint16_t kRouter = 1U << 3;
constexpr uint16_t kDns = 1U << 4;
constexpr uint16_t kLease = 1U << 5;
constexpr uint16_t kT1 = 1U << 6;
constexpr uint16_t kT2 = 1U << 7;
constexpr uint16_t kRequested = 1U << 8;
constexpr uint16_t kOverload = 1U << 9;
constexpr uint32_t kBroadcast = 0xffffffffU;

uint16_t read16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t read32(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
void write16(uint8_t *p, uint16_t value) {
  p[0] = value >> 8;
  p[1] = value & 255;
}
void write32(uint8_t *p, uint32_t value) {
  p[0] = value >> 24;
  p[1] = value >> 16;
  p[2] = value >> 8;
  p[3] = value & 255;
}
bool unicast(uint32_t ip) { return (ip >> 24) != 0 && (ip >> 24) != 127 && (ip >> 24) < 224; }
bool mac_valid(const uint8_t *mac) {
  if (mac == nullptr || (mac[0] & 1) != 0)
    return false;
  uint8_t any = 0;
  for (size_t i = 0; i < 6; ++i)
    any |= mac[i];
  return any != 0;
}
uint32_t sum16(const uint8_t *data, size_t length, uint32_t sum = 0) {
  for (size_t i = 0; i + 1 < length; i += 2)
    sum += read16(data + i);
  if ((length & 1) != 0)
    sum += static_cast<uint16_t>(data[length - 1]) << 8;
  return sum;
}
uint16_t finish_sum(uint32_t sum) {
  while ((sum >> 16) != 0)
    sum = (sum & 0xffffU) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}
bool due(uint32_t now, uint32_t deadline) { return static_cast<int32_t>(now - deadline) >= 0; }

bool read_packet(const PacketReader &reader, size_t length, size_t offset, uint8_t *output, size_t count) {
  return reader.read != nullptr && offset <= length && count <= length - offset &&
         reader.read(reader.context, offset, output, count);
}

bool sum_packet(const PacketReader &reader, size_t packet_length, size_t offset, size_t length, uint32_t &sum,
                uint8_t (&scratch)[64]) {
  // Every non-final chunk has even length, preserving checksum word boundaries
  // independently of the source's fragment boundaries. Pad only the final byte.
  while (length != 0) {
    const size_t count = std::min(length, sizeof(scratch));
    if (!read_packet(reader, packet_length, offset, scratch, count))
      return false;
    sum = sum16(scratch, count, sum);
    offset += count;
    length -= count;
  }
  return true;
}

bool options(const PacketReader &reader, size_t packet_length, size_t offset, size_t length, DhcpMessage &m,
             uint8_t &overload, bool primary) {
  for (size_t pos = 0; pos < length;) {
    uint8_t field[4];
    if (!read_packet(reader, packet_length, offset + pos++, field, 1))
      return false;
    const uint8_t code = field[0];
    if (code == 255)
      return true;
    if (code == 0)
      continue;
    if (pos == length)
      return false;
    if (!read_packet(reader, packet_length, offset + pos++, field, 1))
      return false;
    const size_t count = field[0];
    if (count > length - pos)
      return false;
    uint16_t flag = 0;
    uint32_t *target = nullptr;
    switch (code) {
      case 53:
        flag = kType;
        if (count != 1 || !read_packet(reader, packet_length, offset + pos, field, 1))
          return false;
        m.type = field[0];
        break;
      case 54:
        flag = kServer;
        target = &m.server;
        break;
      case 1:
        flag = kMask;
        target = &m.netmask;
        break;
      case 3:
        flag = kRouter;
        target = &m.router;
        if (count < 4 || count % 4 != 0)
          return false;
        break;
      case 6:
        flag = kDns;
        target = &m.dns;
        if (count < 4 || count % 4 != 0)
          return false;
        break;
      case 51:
        flag = kLease;
        target = &m.lifetime_seconds;
        break;
      case 58:
        flag = kT1;
        target = &m.renewal_seconds;
        break;
      case 59:
        flag = kT2;
        target = &m.rebind_seconds;
        break;
      case 50:
        flag = kRequested;
        target = &m.requested_address;
        break;
      case 52:
        flag = kOverload;
        if (!primary || count != 1 || !read_packet(reader, packet_length, offset + pos, field, 1) || field[0] == 0 ||
            field[0] > 3)
          return false;
        overload = field[0];
        break;
      // Option 61 would change identity relative to ESP-IDF's native STA DHCP.
      // Do not accept client identifiers on forwarded requests in this lab.
      case 61:
        return false;
      default:
        break;
    }
    if (flag != 0) {
      if ((m.present & flag) != 0)
        return false;
      m.present |= flag;
    }
    if (target != nullptr) {
      if (code != 3 && code != 6 && count != 4)
        return false;
      if (!read_packet(reader, packet_length, offset + pos, field, sizeof(field)))
        return false;
      *target = read32(field);
    }
    pos += count;
  }
  // An END marker is required; accepting a truncated option list is unsafe.
  return false;
}

bool parse(const PacketReader &reader, size_t length, bool reply, DhcpMessage &out) {
  out = {};
  uint8_t scratch[64];
  if (length < 20 + 8 + 240 || length > kDhcpPacketCapacity || !read_packet(reader, length, 0, scratch, 20) ||
      (scratch[0] >> 4) != 4)
    return false;
  const size_t ihl = (scratch[0] & 15) * 4U;
  if (ihl < 20 || ihl > length - 8 - 240 || read16(scratch + 2) != length || scratch[9] != 17 ||
      (read16(scratch + 6) & 0xbfffU) != 0)
    return false;
  const uint32_t source = read32(scratch + 12), destination = read32(scratch + 16);
  uint32_t sum = 0;
  if (!sum_packet(reader, length, 0, ihl, sum, scratch) || finish_sum(sum) != 0)
    return false;
  const size_t udp_length = length - ihl;
  if (!read_packet(reader, length, ihl, scratch, 8) || read16(scratch) != (reply ? 67 : 68) ||
      read16(scratch + 2) != (reply ? 68 : 67) || read16(scratch + 4) != udp_length)
    return false;
  if (read16(scratch + 6) != 0) {
    sum = (source >> 16) + (source & 0xffffU) + (destination >> 16) + (destination & 0xffffU) + 17U +
          static_cast<uint32_t>(udp_length);
    if (!sum_packet(reader, length, ihl, udp_length, sum, scratch) || finish_sum(sum) != 0)
      return false;
  }
  const size_t bootp_offset = ihl + 8;
  const size_t b_length = udp_length - 8;
  if (!read_packet(reader, length, bootp_offset, scratch, 34) || scratch[0] != (reply ? 2 : 1) || scratch[1] != 1 ||
      scratch[2] != 6 || scratch[3] != 0 || read32(scratch + 24) != 0 || !mac_valid(scratch + 28))
    return false;
  out.xid = read32(scratch + 4);
  out.source = source;
  out.destination = destination;
  out.client_address = read32(scratch + 12);
  out.offered_address = read32(scratch + 16);
  out.broadcast = (read16(scratch + 10) & 0x8000U) != 0;
  if ((read16(scratch + 10) & 0x7fffU) != 0)
    return false;
  std::memcpy(out.mac, scratch + 28, 6);
  if (!read_packet(reader, length, bootp_offset + 236, scratch, 4) || read32(scratch) != 0x63825363U)
    return false;
  uint8_t overload = 0;
  if (!options(reader, length, bootp_offset + 240, b_length - 240, out, overload, true) ||
      ((overload & 1) != 0 && !options(reader, length, bootp_offset + 108, 128, out, overload, false)) ||
      ((overload & 2) != 0 && !options(reader, length, bootp_offset + 44, 64, out, overload, false)) ||
      (out.present & kType) == 0)
    return false;
  if (reply) {
    if (out.type != 2 && out.type != 5 && out.type != 6)
      return false;
    if (!unicast(out.source) || !unicast(out.server) || (out.present & kServer) == 0)
      return false;
    if (out.destination != kBroadcast && out.destination != out.offered_address &&
        out.destination != out.client_address)
      return false;
    return true;
  }
  if (out.offered_address != 0 || (out.source != 0 && out.source != out.client_address))
    return false;
  if (out.destination != kBroadcast && !unicast(out.destination))
    return false;
  if (out.type == 1)
    return out.broadcast && out.source == 0 && out.client_address == 0 && out.destination == kBroadcast &&
           (out.present & kServer) == 0;
  if (out.type == 3) {
    if (!out.broadcast)
      return false;
    if (out.client_address == 0)
      return out.source == 0 && out.destination == kBroadcast &&
             (out.present & (kServer | kRequested)) == (kServer | kRequested) && unicast(out.server) &&
             unicast(out.requested_address);
    return unicast(out.client_address) && (out.present & (kServer | kRequested)) == 0;
  }
  if (out.type == 4)
    return !out.broadcast && out.source == 0 && out.client_address == 0 && out.destination == kBroadcast &&
           (out.present & (kServer | kRequested)) == (kServer | kRequested) && unicast(out.server) &&
           unicast(out.requested_address);
  if (out.type == 7)
    return !out.broadcast && unicast(out.client_address) && (out.present & kServer) != 0 && unicast(out.server) &&
           out.destination == out.server;
  return false;
}

bool read_contiguous(const void *context, size_t offset, uint8_t *output, size_t count) {
  if (context == nullptr)
    return false;
  std::memcpy(output, static_cast<const uint8_t *>(context) + offset, count);
  return true;
}
}  // namespace

bool parse_dhcp_request(const uint8_t *packet, size_t length, DhcpMessage &message) {
  return parse(PacketReader{packet, read_contiguous}, length, false, message);
}
bool parse_dhcp_reply(const uint8_t *packet, size_t length, DhcpMessage &message) {
  return parse(PacketReader{packet, read_contiguous}, length, true, message);
}
bool parse_dhcp_reply(const PacketReader &reader, size_t length, DhcpMessage &message) {
  return parse(reader, length, true, message);
}

bool DhcpClient::configure(const uint8_t mac[6]) {
  if (!mac_valid(mac))
    return false;
  stop();
  std::memcpy(mac_, mac, 6);
  configured_ = true;
  return true;
}
void DhcpClient::stop() {
  state_ = DhcpState::STOPPED;
  lease_ = {};
  lease_xid_ = 0;
  age_seconds_ = 0;
  age_remainder_ms_ = 0;
  attempts_ = 0;
}
void DhcpClient::start(uint32_t random_xid, uint32_t now_ms) {
  stop();
  if (!configured_)
    return;
  xid_ = random_xid == 0 ? 1 : random_xid;
  clock_ms_ = now_ms;
  discover_(now_ms, false);
}
void DhcpClient::force_revalidate(uint32_t random_xid, uint32_t now_ms) {
  const uint32_t previous_xid = xid_;
  tick(now_ms);
  if (!configured_)
    return;
  xid_ = random_xid == 0 ? 1 : random_xid;
  if (xid_ == previous_xid)
    next_xid_();
  if (!lease_valid(now_ms)) {
    discover_(now_ms, false);
    return;
  }
  // Rebinding must remain broadcast and able to accept another DHCP server.
  // Neither the gateway transition nor this retransmission renews lease age.
  begin_request_(state_ == DhcpState::REBINDING ? DhcpState::REBINDING : DhcpState::RENEWING, now_ms);
}
uint32_t DhcpClient::next_xid_() {
  // Subsequent exchanges use a different xid; xid is a correlation token, not
  // authentication. The first exchange is seeded by the platform random source.
  xid_ += 0x9e3779b9U;
  // Zero marks a missing lease identity in the endpoint control protocol.
  if (xid_ == 0)
    xid_ = 1;
  return xid_;
}
void DhcpClient::discover_(uint32_t now_ms, bool new_xid) {
  if (new_xid)
    next_xid_();
  lease_ = {};
  lease_xid_ = 0;
  age_seconds_ = 0;
  age_remainder_ms_ = 0;
  clock_ms_ = now_ms;
  begin_request_(DhcpState::SELECTING, now_ms);
}
void DhcpClient::begin_request_(DhcpState state, uint32_t now_ms) {
  state_ = state;
  attempts_ = 0;
  due_ms_ = now_ms;
  request_started_ms_ = now_ms;
}
void DhcpClient::tick(uint32_t now_ms) {
  const uint32_t elapsed = now_ms - clock_ms_;
  clock_ms_ = now_ms;
  const uint64_t millis = static_cast<uint64_t>(age_remainder_ms_) + elapsed;
  age_seconds_ += millis / 1000;
  age_remainder_ms_ = millis % 1000;
  if (state_ == DhcpState::BOUND || state_ == DhcpState::RENEWING || state_ == DhcpState::REBINDING) {
    if (lease_.lifetime_seconds != UINT32_MAX && age_seconds_ >= lease_.lifetime_seconds) {
      discover_(now_ms, true);
    } else if (lease_.lifetime_seconds != UINT32_MAX && age_seconds_ >= lease_.rebind_seconds &&
               state_ != DhcpState::REBINDING) {
      begin_request_(DhcpState::REBINDING, now_ms);
    } else if (lease_.lifetime_seconds != UINT32_MAX && age_seconds_ >= lease_.renewal_seconds &&
               state_ == DhcpState::BOUND) {
      next_xid_();
      begin_request_(DhcpState::RENEWING, now_ms);
    }
  } else if (state_ == DhcpState::BACKOFF && due(now_ms, due_ms_)) {
    discover_(now_ms, true);
  } else if (state_ == DhcpState::REQUESTING && attempts_ >= 5 && due(now_ms, due_ms_)) {
    discover_(now_ms, true);
  }
}
bool DhcpClient::lease_valid(uint32_t now_ms) const {
  if (state_ != DhcpState::BOUND && state_ != DhcpState::RENEWING && state_ != DhcpState::REBINDING)
    return false;
  if (lease_.lifetime_seconds == UINT32_MAX)
    return true;
  const uint64_t age =
      age_seconds_ + (static_cast<uint64_t>(age_remainder_ms_) + static_cast<uint32_t>(now_ms - clock_ms_)) / 1000;
  return age < lease_.lifetime_seconds;
}
uint32_t DhcpClient::remaining_seconds(uint32_t now_ms) const {
  if (!lease_valid(now_ms))
    return 0;
  if (lease_.lifetime_seconds == UINT32_MAX)
    return UINT32_MAX;
  const uint64_t elapsed_ms = static_cast<uint64_t>(age_remainder_ms_) + static_cast<uint32_t>(now_ms - clock_ms_);
  const uint64_t age = age_seconds_ + (elapsed_ms + 999) / 1000;
  return age >= lease_.lifetime_seconds ? 0 : lease_.lifetime_seconds - static_cast<uint32_t>(age);
}
bool DhcpClient::valid_lease_(DhcpLease &lease) const {
  if (!unicast(lease.address) || !unicast(lease.server) || !unicast(lease.router) || lease.lifetime_seconds < 4)
    return false;
  const uint32_t inverse = ~lease.netmask;
  if (lease.netmask == 0 || inverse < 3 || (inverse & (inverse + 1)) != 0 || (lease.address & inverse) == 0 ||
      (lease.address & inverse) == inverse || (lease.router & lease.netmask) != (lease.address & lease.netmask) ||
      lease.router == lease.address || (lease.router & inverse) == 0 || (lease.router & inverse) == inverse ||
      (lease.dns != 0 && !unicast(lease.dns)))
    return false;
  if (lease.lifetime_seconds == UINT32_MAX) {
    lease.renewal_seconds = lease.rebind_seconds = UINT32_MAX;
    return true;
  }
  if (lease.renewal_seconds == 0)
    lease.renewal_seconds = lease.lifetime_seconds / 2;
  if (lease.rebind_seconds == 0)
    lease.rebind_seconds = static_cast<uint32_t>(static_cast<uint64_t>(lease.lifetime_seconds) * 7 / 8);
  return lease.renewal_seconds > 0 && lease.renewal_seconds < lease.rebind_seconds &&
         lease.rebind_seconds < lease.lifetime_seconds;
}
DhcpResult DhcpClient::receive(const uint8_t *packet, size_t length, uint32_t now_ms) {
  tick(now_ms);
  if (state_ == DhcpState::STOPPED || state_ == DhcpState::BOUND || state_ == DhcpState::BACKOFF ||
      state_ == DhcpState::DECLINING)
    return DhcpResult::IGNORED;
  DhcpMessage m;
  if (!parse_dhcp_reply(packet, length, m) || m.xid != xid_ || std::memcmp(mac_, m.mac, 6) != 0)
    return DhcpResult::IGNORED;
  const bool selecting = state_ == DhcpState::SELECTING;
  if (!selecting && state_ != DhcpState::REBINDING && m.server != lease_.server)
    return DhcpResult::IGNORED;
  if (m.type == 6 && !selecting) {
    lease_ = {};
    lease_xid_ = 0;
    state_ = DhcpState::BACKOFF;
    due_ms_ = now_ms + 1000;
    return DhcpResult::LEASE_REJECTED;
  }
  if ((selecting && m.type != 2) || (!selecting && m.type != 5))
    return DhcpResult::IGNORED;
  DhcpLease candidate{};
  candidate.address = m.offered_address;
  candidate.server = m.server;
  candidate.netmask = m.netmask;
  candidate.router = m.router;
  candidate.dns = m.dns;
  candidate.lifetime_seconds = m.lifetime_seconds;
  candidate.renewal_seconds = m.renewal_seconds;
  candidate.rebind_seconds = m.rebind_seconds;
  if ((m.present & (kMask | kRouter | kLease)) != (kMask | kRouter | kLease) || !valid_lease_(candidate) ||
      (!selecting && candidate.address != lease_.address))
    return DhcpResult::IGNORED;
  lease_ = candidate;
  if (selecting) {
    begin_request_(DhcpState::REQUESTING, now_ms);
    return DhcpResult::OFFER_ACCEPTED;
  }
  age_seconds_ = 0;
  age_remainder_ms_ = 0;
  clock_ms_ = now_ms;
  state_ = DhcpState::BOUND;
  lease_xid_ = xid_;
  attempts_ = 0;
  return DhcpResult::LEASE_BOUND;
}
bool DhcpClient::decline(uint32_t now_ms) {
  tick(now_ms);
  if (!lease_valid(now_ms))
    return false;
  begin_request_(DhcpState::DECLINING, now_ms);
  return true;
}
bool DhcpClient::build_(uint8_t *output, size_t capacity, size_t &written) const {
  written = 0;
  constexpr size_t length = 328;  // Minimum 300-byte DHCP payload.
  if (output == nullptr || capacity < length)
    return false;
  std::memset(output, 0, length);
  output[0] = 0x45;
  write16(output + 2, length);
  write16(output + 4, static_cast<uint16_t>(xid_));
  output[8] = 64;
  output[9] = 17;
  const bool has_ciaddr = state_ == DhcpState::RENEWING || state_ == DhcpState::REBINDING;
  write32(output + 12, has_ciaddr ? lease_.address : 0);
  write32(output + 16, state_ == DhcpState::RENEWING ? lease_.server : kBroadcast);
  uint8_t *udp = output + 20;
  write16(udp, 68);
  write16(udp + 2, 67);
  write16(udp + 4, length - 20);
  uint8_t *b = udp + 8;
  b[0] = b[1] = 1;
  b[2] = 6;
  write32(b + 4, xid_);
  write16(b + 10, state_ == DhcpState::DECLINING ? 0 : 0x8000);
  write32(b + 12, has_ciaddr ? lease_.address : 0);
  std::memcpy(b + 28, mac_, 6);
  write32(b + 236, 0x63825363);
  size_t pos = 240;
  b[pos++] = 53;
  b[pos++] = 1;
  b[pos++] = state_ == DhcpState::SELECTING ? 1 : (state_ == DhcpState::DECLINING ? 4 : 3);
  if (state_ == DhcpState::REQUESTING || state_ == DhcpState::DECLINING) {
    b[pos++] = 50;
    b[pos++] = 4;
    write32(b + pos, lease_.address);
    pos += 4;
    b[pos++] = 54;
    b[pos++] = 4;
    write32(b + pos, lease_.server);
    pos += 4;
  }
  if (state_ != DhcpState::DECLINING) {
    b[pos++] = 55;
    b[pos++] = 7;
    for (uint8_t option : {1, 3, 6, 51, 54, 58, 59})
      b[pos++] = option;
    b[pos++] = 57;
    b[pos++] = 2;
    write16(b + pos, 1472);
    pos += 2;
  }
  b[pos] = 255;
  write16(output + 10, finish_sum(sum16(output, 20)));
  uint32_t sum = sum16(output + 12, 8) + 17U + static_cast<uint32_t>(length - 20);
  uint16_t checksum = finish_sum(sum16(udp, length - 20, sum));
  write16(udp + 6, checksum == 0 ? 0xffff : checksum);
  written = length;
  return true;
}
bool DhcpClient::poll(uint32_t now_ms, uint8_t *output, size_t capacity, size_t &written) {
  written = 0;
  tick(now_ms);
  if (state_ == DhcpState::STOPPED || state_ == DhcpState::BOUND || state_ == DhcpState::BACKOFF ||
      !due(now_ms, due_ms_) || !build_(output, capacity, written))
    return false;
  // RFC secs field: acquisition/renewal time, saturated rather than wrapping.
  write16(output + 28 + 8, state_ == DhcpState::DECLINING ? 0
                                                          : static_cast<uint16_t>(std::min<uint32_t>(
                                                                (now_ms - request_started_ms_) / 1000, 65535)));
  // Changing secs requires recomputing the UDP checksum.
  write16(output + 26, 0);
  uint32_t sum = sum16(output + 12, 8) + 17U + static_cast<uint32_t>(written - 20);
  uint16_t checksum = finish_sum(sum16(output + 20, written - 20, sum));
  write16(output + 26, checksum == 0 ? 0xffff : checksum);
  if (state_ == DhcpState::DECLINING) {
    lease_ = {};
    lease_xid_ = 0;
    state_ = DhcpState::BACKOFF;
    due_ms_ = now_ms + 10000;
    return true;
  }
  const uint32_t interval = 1000U << std::min<uint8_t>(attempts_, 4);
  if (attempts_ < 255)
    ++attempts_;
  due_ms_ = now_ms + interval + (xid_ & 255U);
  return true;
}
}  // namespace mesh_ip
