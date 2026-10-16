#pragma once

#include "mesh_limits.h"
#ifdef MESH_IPV6
#include "mesh_ip_ipv6.h"
#endif

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>

namespace mesh_ip {

// A descriptor carries the node's actual ESPHome API records, never gateway
// metadata. Only this small control message is relayed; mDNS is LAN-local.
constexpr size_t DISCOVERY_DESCRIPTOR_MAX = 768;
constexpr size_t DISCOVERY_FRAME_MAX = 160;
constexpr size_t DISCOVERY_FRAME_MIN = 43;
constexpr size_t DISCOVERY_HEADER_SIZE = 16;
#ifdef MESH_IPV6
constexpr size_t DISCOVERY_IPV6_HEADER_SIZE = 28;
constexpr size_t DISCOVERY_IPV6_FRAME_MIN = 52;
#endif
constexpr size_t DISCOVERY_CHUNK_SIZE = DISCOVERY_FRAME_MAX - DISCOVERY_HEADER_SIZE;
constexpr uint8_t DISCOVERY_CONTROL = 7;
constexpr uint32_t DISCOVERY_LIFETIME_MS = 15000;

#ifndef MESH_DISCOVERY_ASSEMBLY_SLOTS
#define MESH_DISCOVERY_ASSEMBLY_SLOTS MESH_MAX_NODES
#endif
constexpr size_t DISCOVERY_ASSEMBLY_SLOTS = MESH_DISCOVERY_ASSEMBLY_SLOTS;
static_assert(DISCOVERY_ASSEMBLY_SLOTS >= 1 && DISCOVERY_ASSEMBLY_SLOTS <= mesh_limits::MAX_NODES,
              "Discovery assembly slots must be between one and max_nodes");

constexpr size_t DISCOVERY_TXT_MAX = 16;

struct DiscoveryTxt {
  std::string_view key, value;
};

// All text shares one bounded arena. The wire's two length bytes per TXT item
// leave room for two terminators, so every valid 768-byte descriptor fits.
class DiscoveryDescriptor {
 public:
  DiscoveryDescriptor() = default;
  DiscoveryDescriptor(std::string_view hostname, uint16_t api, uint16_t http, std::initializer_list<DiscoveryTxt> txt);
  void clear();
  bool set_hostname(std::string_view hostname);
  bool add_txt(std::string_view key, std::string_view value);
  bool set_txt_value(size_t index, std::string_view value);
  std::string_view hostname() const { return {this->text_.data(), this->hostname_length_}; }
  size_t txt_count() const { return this->txt_count_; }
  DiscoveryTxt txt(size_t index) const;
  bool storage_valid() const { return this->storage_valid_; }
  uint16_t api_port{0}, http_port{0};

 private:
  struct TxtOffset {
    uint16_t key{0}, value{0};
    uint8_t key_length{0}, value_length{0};
  };
  bool replace_text_(uint16_t offset, uint8_t previous_length, std::string_view value);
  std::array<char, DISCOVERY_DESCRIPTOR_MAX> text_{};
  std::array<TxtOffset, DISCOVERY_TXT_MAX> txt_{};
  uint16_t used_{1};
  uint8_t hostname_length_{0}, txt_count_{0};
  bool storage_valid_{true};
};

// Metadata is bound to one currently usable address. The gateway obtains the
// full A/AAAA set separately from its validated endpoint ownership snapshots.
struct DiscoveryAddress {
  uint32_t ipv4{0};
  DiscoveryAddress(uint32_t address = 0) : ipv4(address) {}
#ifdef MESH_IPV6
  Ipv6Address ipv6{};
  bool is_ipv6{false};
  DiscoveryAddress(const Ipv6Address &address) : ipv6(address), is_ipv6(true) {}
#endif
  bool valid() const;
  bool operator==(const DiscoveryAddress &other) const;
  bool operator!=(const DiscoveryAddress &other) const { return !(*this == other); }
};

bool encode_discovery(const DiscoveryDescriptor &descriptor, uint8_t *output, size_t capacity, size_t &written);
bool decode_discovery(const uint8_t *data, size_t length, DiscoveryDescriptor &descriptor);
uint32_t discovery_digest(const uint8_t *data, size_t length);
// Addresses are opaque four-byte lwIP IPv4 addresses, matching IP_STATUS.
bool discovery_chunk(const uint8_t *data, size_t length, uint32_t address, size_t offset, uint8_t *output,
                     size_t capacity, size_t &written, size_t payload_budget = DISCOVERY_FRAME_MAX);
#ifdef MESH_IPV6
bool discovery_chunk(const uint8_t *data, size_t length, const Ipv6Address &address, size_t offset, uint8_t *output,
                     size_t capacity, size_t &written, size_t payload_budget = DISCOVERY_FRAME_MAX);
#endif

class DiscoveryRegistry {
 public:
  static constexpr size_t assembly_capacity() { return DISCOVERY_ASSEMBLY_SLOTS; }
  bool authorize(uint8_t node, const uint8_t *mac);
  void revoke(uint8_t node);  // Main-loop owner only; removes authorization too.
  bool receive(uint8_t node, const uint8_t *data, size_t length, uint32_t now);
  const DiscoveryDescriptor *current(uint8_t node, uint32_t address, uint32_t now) const;
#ifdef MESH_IPV6
  const DiscoveryDescriptor *current(uint8_t node, const Ipv6Address &address, uint32_t now) const;
  bool refresh(uint8_t node, const Ipv6Address &address, uint32_t now);
#endif
  uint32_t revision(uint8_t node) const;
  // Only a separately validated, fresh IP_STATUS for this same lease owner
  // may maintain an existing descriptor. Never invent or revive metadata.
  bool refresh(uint8_t node, uint32_t address, uint32_t now);
  void forget(uint8_t node);
  void expire(uint32_t now);

 private:
  const DiscoveryDescriptor *current_(uint8_t node, const DiscoveryAddress &address, uint32_t now) const;
  bool refresh_(uint8_t node, const DiscoveryAddress &address, uint32_t now);
  struct Assembly {
    std::array<uint8_t, DISCOVERY_DESCRIPTOR_MAX> data{};
    DiscoveryAddress address{};
    uint32_t digest{0}, started{0};
    uint16_t length{0};
    uint32_t chunks{0};
    uint8_t stride{0};
    bool active{false};
    uint8_t owner{0};
  };
  struct Peer {
    uint8_t mac[6]{};
    bool authorized{false};
    DiscoveryDescriptor descriptor{};
    bool descriptor_valid{false};
    DiscoveryAddress address{};
    uint32_t digest{0}, seen{0}, revision{0};
  };
  Assembly *assembly_(uint8_t node);
  void clear_assembly_(uint8_t node);
  void admit_waiters_(uint32_t now);
  void expire_assemblies_(uint32_t now);
  Peer peers_[mesh_limits::MAX_NODES]{};
  // A reduced local pool trades simultaneous reception for bounded RAM. Its
  // fixed grants cannot be extended by changing a digest or by duplicates.
  Assembly assemblies_[DISCOVERY_ASSEMBLY_SLOTS]{};
  uint16_t waiting_{0};
  uint8_t admission_cursor_{0};
};

}  // namespace mesh_ip
