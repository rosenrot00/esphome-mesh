#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace mesh_ip {

struct Ipv6Address {
  std::array<uint8_t, 16> bytes{};
  bool operator==(const Ipv6Address &other) const { return bytes == other.bytes; }
  bool operator!=(const Ipv6Address &other) const { return !(*this == other); }
  bool unspecified() const;
  bool multicast() const { return bytes[0] == 0xff; }
  bool link_local() const { return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80; }
  bool matches_eui64(const uint8_t mac[6]) const;
  Ipv6Address solicited_node() const;
};

// Read-only, coherent publication by the TCP/IP owner. Tentative and duplicate
// addresses are never reported as ready; lifetime remains owned by lwIP.
struct Ipv6AddressSnapshot {
  static constexpr size_t CAPACITY = 3;
  Ipv6Address addresses[CAPACITY]{};
  uint32_t generation{0}, peer_epoch{0};
  uint8_t count{0};
  // Local address preference only; the claim/grant wire format carries valid
  // addresses, not this hint. Deprecated addresses remain usable until expiry.
  uint8_t preferred_mask{0};
  bool ready{false};
};

// Offsets are relative to the IPv6 header. Reads copy exactly count bytes or
// fail; the caller keeps the complete packet stable for the inspection.
struct Ipv6PacketReader {
  const void *context{nullptr};
  bool (*read)(const void *, size_t, uint8_t *, size_t){nullptr};
};
struct Ipv6PacketInfo {
  Ipv6Address source{}, destination{}, target{};
  uint16_t total_length{0}, upper_offset{0}, upper_length{0}, options_offset{0};
  uint8_t next_header{0}, icmp_type{0}, hop_limit{0};
  bool fragmented{false}, noninitial_fragment{false}, protected_payload{false}, nd{false}, dad{false};
};

// Bounded IPv6/extension-header parsing. ND additionally requires a valid
// ICMPv6 checksum, hop limit 255, code zero and well-formed options. Fragmented
// ND is rejected per RFC 6980; ordinary IP fragments remain opaque IP traffic.
bool inspect_ipv6(const Ipv6PacketReader &reader, size_t length, Ipv6PacketInfo &info);
bool inspect_ipv6(const uint8_t *packet, size_t length, Ipv6PacketInfo &info);
// Only changes the six bytes of a valid ND SLLA/TLLA option and its checksum.
// Authenticated SEND messages cannot be rewritten and are rejected. A packet
// without a link-address option is valid and remains unchanged (e.g. DAD).
bool rewrite_nd_link_address(uint8_t *packet, size_t length, const uint8_t mac[6]);
// For a newly constructed ICMPv6 packet, including a checksum-zero DAD NS.
// Validates packet layout/ND rules before calculating the checksum. Does not
// rewrite authenticated or fragmented messages.
bool finalize_icmpv6_checksum(uint8_t *packet, size_t length);

}  // namespace mesh_ip
