#include "mesh_ip_ipv6.h"

#include <algorithm>
#include <cstring>

namespace mesh_ip {
namespace {
constexpr size_t IPV6_HEADER = 40, MAX_PACKET = 1500;
uint16_t be16(const uint8_t *p) { return (uint16_t(p[0]) << 8) | p[1]; }
bool read(const Ipv6PacketReader &reader, size_t length, size_t offset, uint8_t *out, size_t count) {
  return reader.read != nullptr && offset <= length && count <= length - offset &&
         reader.read(reader.context, offset, out, count);
}
bool contiguous_read(const void *context, size_t offset, uint8_t *out, size_t count) {
  if (context == nullptr)
    return false;
  std::memcpy(out, static_cast<const uint8_t *>(context) + offset, count);
  return true;
}
uint32_t add_bytes(uint32_t sum, const uint8_t *bytes, size_t length) {
  for (size_t i = 0; i + 1 < length; i += 2)
    sum += be16(bytes + i);
  if (length & 1)
    sum += uint16_t(bytes[length - 1]) << 8;
  return sum;
}
bool checksum(const Ipv6PacketReader &reader, size_t length, const Ipv6PacketInfo &info, uint16_t &value) {
  uint32_t sum = add_bytes(0, info.source.bytes.data(), 16);
  sum = add_bytes(sum, info.destination.bytes.data(), 16);
  sum += info.upper_length;
  sum += 58;  // Pseudo-header uses the upper protocol, not an extension header.
  uint8_t scratch[64];
  for (size_t offset = info.upper_offset; offset < length; offset += sizeof(scratch)) {
    const size_t count = std::min(sizeof(scratch), length - offset);
    if (!read(reader, length, offset, scratch, count))
      return false;
    sum = add_bytes(sum, scratch, count);
  }
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  value = static_cast<uint16_t>(~sum);
  return true;
}
bool nd_options(const Ipv6PacketReader &reader, size_t length, const Ipv6PacketInfo &info) {
  uint8_t option[2];
  for (size_t offset = info.options_offset; offset < length;) {
    if (!read(reader, length, offset, option, sizeof(option)) || option[1] == 0)
      return false;
    const size_t count = size_t(option[1]) * 8;
    if (count > length - offset)
      return false;
    if ((option[0] == 1 || option[0] == 2 || option[0] == 5) && count != 8)
      return false;
    if (option[0] == 3 && count != 32)
      return false;
    if (info.source.unspecified() && option[0] == 1)
      return false;
    offset += count;
  }
  return true;
}
}  // namespace

bool Ipv6Address::unspecified() const {
  for (const auto byte : bytes)
    if (byte != 0)
      return false;
  return true;
}
bool Ipv6Address::matches_eui64(const uint8_t mac[6]) const {
  return mac != nullptr && bytes[8] == (mac[0] ^ 2) && bytes[9] == mac[1] && bytes[10] == mac[2] && bytes[11] == 0xff &&
         bytes[12] == 0xfe && bytes[13] == mac[3] && bytes[14] == mac[4] && bytes[15] == mac[5];
}
Ipv6Address Ipv6Address::solicited_node() const {
  Ipv6Address address{};
  address.bytes[0] = 0xff;
  address.bytes[1] = 2;
  address.bytes[11] = 1;
  address.bytes[12] = 0xff;
  std::copy(bytes.begin() + 13, bytes.end(), address.bytes.begin() + 13);
  return address;
}

static bool inspect_ipv6_impl(const Ipv6PacketReader &reader, size_t length, Ipv6PacketInfo &info,
                              bool validate_checksum) {
  info = {};
  uint8_t header[40];
  if (length < IPV6_HEADER || length > MAX_PACKET || !read(reader, length, 0, header, sizeof(header)) ||
      (header[0] >> 4) != 6 || size_t(be16(header + 4)) + IPV6_HEADER != length)
    return false;
  std::copy(header + 8, header + 24, info.source.bytes.begin());
  std::copy(header + 24, header + 40, info.destination.bytes.begin());
  if (info.source.multicast() || info.destination.unspecified())
    return false;
  info.total_length = static_cast<uint16_t>(length);
  info.hop_limit = header[7];
  uint8_t next = header[6];
  size_t offset = IPV6_HEADER;
  bool protected_payload = false;
  while (next == 0 || next == 43 || next == 60 || next == 44 || next == 51) {
    uint8_t extension[8];
    if (!read(reader, length, offset, extension, sizeof(extension)))
      return false;
    const uint8_t following = extension[0];
    size_t count;
    if (next == 44) {
      if (info.fragmented || extension[1] != 0 || (be16(extension + 2) & 6) != 0)
        return false;
      info.fragmented = true;
      info.noninitial_fragment = (be16(extension + 2) & 0xfff8) != 0;
      count = 8;
    } else if (next == 51) {
      count = (size_t(extension[1]) + 2) * 4;
      if (count < 12)
        return false;
      protected_payload = true;
    } else {
      if (next == 0 && offset != IPV6_HEADER)
        return false;
      count = (size_t(extension[1]) + 1) * 8;
    }
    if (count > length - offset)
      return false;
    offset += count;
    next = following;
    // Later fragments need not start with a complete upper-layer header.
    if (info.noninitial_fragment)
      break;
  }
  info.next_header = next;
  info.protected_payload = protected_payload;
  info.upper_offset = static_cast<uint16_t>(offset);
  info.upper_length = static_cast<uint16_t>(length - offset);
  if (info.noninitial_fragment || next != 58)
    return true;
  uint8_t icmp[24];
  if (!read(reader, length, offset, icmp, 4))
    return false;
  info.icmp_type = icmp[0];
  if (icmp[0] < 133 || icmp[0] > 137)
    return true;
  info.nd = true;
  if (info.fragmented || protected_payload || info.hop_limit != 255 || icmp[1] != 0)
    return false;
  const size_t body = icmp[0] == 133 ? 8 : (icmp[0] == 134 ? 16 : (icmp[0] == 137 ? 40 : 24));
  if (length - offset < body)
    return false;
  info.options_offset = static_cast<uint16_t>(offset + body);
  if (icmp[0] == 134 || icmp[0] == 137) {
    if (!info.source.link_local())
      return false;
  } else if (icmp[0] != 133) {
    if (!read(reader, length, offset, icmp, sizeof(icmp)))
      return false;
    std::copy(icmp + 8, icmp + 24, info.target.bytes.begin());
    if (info.target.multicast() || info.target.unspecified())
      return false;
    if (icmp[0] == 135) {
      info.dad = info.source.unspecified();
      if (info.dad && info.destination != info.target.solicited_node())
        return false;
    } else if (info.source.unspecified() || ((icmp[4] & 0x40) != 0 && info.destination.multicast())) {
      return false;
    }
  }
  if (icmp[0] == 137) {
    uint8_t redirect[32];
    if (!read(reader, length, offset + 8, redirect, sizeof(redirect)))
      return false;
    std::copy(redirect, redirect + 16, info.target.bytes.begin());
    Ipv6Address redirected_destination{};
    std::copy(redirect + 16, redirect + 32, redirected_destination.bytes.begin());
    if (info.destination.multicast() || redirected_destination.multicast() || redirected_destination.unspecified() ||
        (!info.target.link_local() && info.target != redirected_destination))
      return false;
  }
  uint16_t value;
  return nd_options(reader, length, info) &&
         (!validate_checksum || (checksum(reader, length, info, value) && value == 0));
}

bool inspect_ipv6(const uint8_t *packet, size_t length, Ipv6PacketInfo &info) {
  return packet != nullptr && inspect_ipv6({packet, contiguous_read}, length, info);
}
bool inspect_ipv6(const Ipv6PacketReader &reader, size_t length, Ipv6PacketInfo &info) {
  return inspect_ipv6_impl(reader, length, info, true);
}
bool finalize_icmpv6_checksum(uint8_t *packet, size_t length) {
  Ipv6PacketInfo info;
  if (packet == nullptr || !inspect_ipv6_impl({packet, contiguous_read}, length, info, false) ||
      info.next_header != 58 || info.fragmented || info.protected_payload)
    return false;
  if (info.nd)
    for (size_t offset = info.options_offset; offset < length; offset += size_t(packet[offset + 1]) * 8)
      if (packet[offset] == 12)
        return false;
  packet[info.upper_offset + 2] = packet[info.upper_offset + 3] = 0;
  uint16_t value;
  if (!checksum({packet, contiguous_read}, length, info, value))
    return false;
  packet[info.upper_offset + 2] = static_cast<uint8_t>(value >> 8);
  packet[info.upper_offset + 3] = static_cast<uint8_t>(value);
  return true;
}

bool rewrite_nd_link_address(uint8_t *packet, size_t length, const uint8_t mac[6]) {
  Ipv6PacketInfo info;
  bool nonzero_mac = false;
  if (mac != nullptr)
    for (size_t i = 0; i < 6; ++i)
      nonzero_mac |= mac[i] != 0;
  if (mac == nullptr || (mac[0] & 1) != 0 || !nonzero_mac || !inspect_ipv6(packet, length, info) || !info.nd)
    return false;
  bool changed = false;
  // Validate the entire option list before mutation. SEND's RSA signature
  // covers the ND message and would be invalidated by any LLA rewrite.
  for (size_t offset = info.options_offset; offset < length; offset += size_t(packet[offset + 1]) * 8)
    if (packet[offset] == 12)
      return false;
  for (size_t offset = info.options_offset; offset < length; offset += size_t(packet[offset + 1]) * 8) {
    if (packet[offset] == 1 || packet[offset] == 2) {
      std::memcpy(packet + offset + 2, mac, 6);
      changed = true;
    }
  }
  if (!changed)
    return true;
  packet[info.upper_offset + 2] = packet[info.upper_offset + 3] = 0;
  uint16_t value;
  if (!checksum({packet, contiguous_read}, length, info, value))
    return false;
  packet[info.upper_offset + 2] = static_cast<uint8_t>(value >> 8);
  packet[info.upper_offset + 3] = static_cast<uint8_t>(value);
  return true;
}

}  // namespace mesh_ip
