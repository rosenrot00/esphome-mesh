#pragma once

#include "mesh_limits.h"

#include <cstddef>
#include <cstdint>

// Small, allocation-free DHCPv4 client for a mesh link with a LAN gateway.
// Addresses are numeric network-order values (192.168.1.2 == 0xc0a80102),
// independent of host byte order. Instances require serialized access.
namespace mesh_ip {

constexpr size_t kDhcpPacketCapacity = 1500;

enum class DhcpState : uint8_t { STOPPED, SELECTING, REQUESTING, BOUND, RENEWING, REBINDING, DECLINING, BACKOFF };
enum class DhcpResult : uint8_t { IGNORED, OFFER_ACCEPTED, LEASE_BOUND, LEASE_REJECTED };

struct DhcpLease {
  uint32_t address{0};
  uint32_t netmask{0};
  uint32_t router{0};
  uint32_t dns{0};
  uint32_t server{0};
  uint32_t lifetime_seconds{0};
  uint32_t renewal_seconds{0};
  uint32_t rebind_seconds{0};
};

struct DhcpMessage {
  uint8_t type{0};
  uint8_t mac[6]{};
  uint32_t xid{0};
  uint32_t source{0};
  uint32_t destination{0};
  uint32_t client_address{0};
  uint32_t offered_address{0};
  uint32_t requested_address{0};
  uint32_t server{0};
  uint32_t netmask{0};
  uint32_t router{0};
  uint32_t dns{0};
  uint32_t lifetime_seconds{0};
  uint32_t renewal_seconds{0};
  uint32_t rebind_seconds{0};
  uint16_t present{0};
  bool broadcast{false};
};

// Read-only view of a possibly fragmented packet. The owner keeps the bytes
// stable for the entire parse; read must copy exactly count bytes or return
// false. Offsets are relative to the IPv4 header, not a link-layer header.
struct PacketReader {
  const void *context{nullptr};
  bool (*read)(const void *context, size_t offset, uint8_t *output, size_t count){nullptr};
};

// Strict bounded IPv4/UDP/BOOTP parsing, including IP and nonzero UDP checksums,
// no IP fragments, no relay giaddr, matching Ethernet MAC and DHCP cookie.
// Request parser accepts only DISCOVER, REQUEST, DECLINE and RELEASE. The gateway
// must additionally match mac to the authenticated mesh source's configured STA
// MAC, and bind replies to a live (source, xid, mac) transaction.
bool parse_dhcp_request(const uint8_t *packet, size_t length, DhcpMessage &message);
bool parse_dhcp_reply(const uint8_t *packet, size_t length, DhcpMessage &message);
bool parse_dhcp_reply(const PacketReader &reader, size_t length, DhcpMessage &message);

class DhcpClient {
 public:
  bool configure(const uint8_t mac[6]);
  // xid must come from platform entropy, never the node ID or a persisted IP.
  // No previous lease is assumed by this entry point.
  void start(uint32_t random_xid, uint32_t now_ms);
  // Revalidate a still-valid lease through a new mesh gateway using a fresh
  // transaction and ciaddr. The original age remains authoritative until ACK;
  // an absent/expired lease instead starts normal cold DHCP discovery.
  void force_revalidate(uint32_t random_xid, uint32_t now_ms);
  void stop();
  // Call regularly, even when the mesh route is unavailable. Lease time is
  // counted in seconds without multiplying long leases into a wrapping millis
  // deadline. Calls must be separated by less than one uint32_t clock wrap.
  void tick(uint32_t now_ms);
  // Call when the packet transport can accept a packet. A true return consumes
  // one logical transmission; dropped packets are retried with bounded backoff.
  bool poll(uint32_t now_ms, uint8_t *output, size_t capacity, size_t &written);
  DhcpResult receive(const uint8_t *packet, size_t length, uint32_t now_ms);
  // When LAN-side ARP probing detects a conflicting address after ACK, do not
  // install/advertise the lease. Send DECLINE and wait ten seconds to retry.
  bool decline(uint32_t now_ms);
  DhcpState state() const { return state_; }
  const DhcpLease &lease() const { return lease_; }
  uint32_t xid() const { return xid_; }
  // Transaction that last established this lease; unlike xid(), stable while
  // renewal or gateway revalidation is awaiting a new server ACK.
  uint32_t lease_xid() const { return lease_xid_; }
  bool lease_valid(uint32_t now_ms) const;
  // Conservative whole seconds; the endpoint, never a route, owns this clock.
  uint32_t remaining_seconds(uint32_t now_ms) const;

 private:
  void discover_(uint32_t now_ms, bool new_xid);
  void begin_request_(DhcpState state, uint32_t now_ms);
  bool build_(uint8_t *output, size_t capacity, size_t &written) const;
  bool valid_lease_(DhcpLease &lease) const;
  uint32_t next_xid_();

  DhcpLease lease_{};
  uint8_t mac_[6]{};
  DhcpState state_{DhcpState::STOPPED};
  uint32_t xid_{0};
  uint32_t lease_xid_{0};
  uint32_t clock_ms_{0};
  uint32_t age_remainder_ms_{0};
  uint64_t age_seconds_{0};
  uint32_t due_ms_{0};
  uint32_t request_started_ms_{0};
  uint8_t attempts_{0};
  bool configured_{false};
};

}  // namespace mesh_ip
