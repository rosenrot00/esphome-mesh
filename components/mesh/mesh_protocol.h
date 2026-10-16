#pragma once

#include "mesh_limits.h"

#include <cstddef>
#include <cstdint>

namespace mesh_protocol {

constexpr size_t PROFILE_WIRE_SIZE = 9;
constexpr uint8_t STATIC_FRAME_VERSION = 5;
constexpr uint8_t SESSION_FRAME_VERSION = 6;
constexpr uint16_t IP_PACKET_ACK = 1U << 0;
constexpr uint16_t ENDPOINT_SESSION_PROOF = 1U << 1;
constexpr uint16_t VARIABLE_FRAGMENT_SIZE = 1U << 2;
constexpr uint16_t WIDE_FRAME_LENGTH = 1U << 3;
constexpr uint16_t WIDE_FRAGMENT_STRIDE = 1U << 4;
constexpr uint16_t IPV6_PROXY = 1U << 5;
constexpr uint16_t MANUAL_BOOT_SESSION = 1U << 6;
#ifdef MESH_IPV6
constexpr uint16_t REQUIRED_IPV6 = IPV6_PROXY;
#else
constexpr uint16_t REQUIRED_IPV6 = 0;
#endif

// A protocol contract, not a firmware release number. Optional future features
// remain compatible; a required feature must be implemented at both ends.
// This revision uses one common payload budget throughout the mesh.
struct Profile {
  uint8_t frame_version{SESSION_FRAME_VERSION};
  uint8_t endpoint_revision{1};
  uint16_t payload_budget{mesh_limits::PROTOCOL_PAYLOAD_BUDGET};
  uint8_t max_nodes{mesh_limits::MAX_NODES};
  uint16_t provided{IP_PACKET_ACK | ENDPOINT_SESSION_PROOF | VARIABLE_FRAGMENT_SIZE | WIDE_FRAME_LENGTH |
                    WIDE_FRAGMENT_STRIDE | REQUIRED_IPV6};
  uint16_t required{IP_PACKET_ACK | ENDPOINT_SESSION_PROOF | WIDE_FRAME_LENGTH | WIDE_FRAGMENT_STRIDE | REQUIRED_IPV6};
};
// Manual peers have no automatic admission exchange. Their separate bootstrap
// proves this exact protocol contract before admitting session-scoped traffic.
constexpr Profile manual_profile() {
  Profile profile;
  profile.provided |= MANUAL_BOOT_SESSION;
  profile.required |= MANUAL_BOOT_SESSION;
  return profile;
}
constexpr bool valid(const Profile &profile) {
  return profile.frame_version != 0 && profile.endpoint_revision != 0 &&
         (profile.max_nodes == 4 || profile.max_nodes == 8 || profile.max_nodes == 16) &&
         profile.payload_budget >= 43 && profile.payload_budget <= mesh_limits::PROTOCOL_PAYLOAD_BUDGET &&
         (profile.required & ~profile.provided) == 0;
}
constexpr bool same(const Profile &first, const Profile &second) {
  return first.frame_version == second.frame_version && first.endpoint_revision == second.endpoint_revision &&
         first.payload_budget == second.payload_budget && first.max_nodes == second.max_nodes &&
         first.provided == second.provided && first.required == second.required;
}
constexpr bool compatible(const Profile &local, const Profile &remote) {
  return valid(local) && valid(remote) && local.frame_version == remote.frame_version &&
         local.endpoint_revision == remote.endpoint_revision && local.payload_budget == remote.payload_budget &&
         local.max_nodes == remote.max_nodes && (local.required & ~remote.provided) == 0 &&
         (remote.required & ~local.provided) == 0;
}
inline bool encode(const Profile &profile, uint8_t *output, size_t capacity) {
  if (!valid(profile) || output == nullptr || capacity < PROFILE_WIRE_SIZE)
    return false;
  output[0] = profile.frame_version;
  output[1] = profile.endpoint_revision;
  output[2] = static_cast<uint8_t>(profile.payload_budget);
  output[3] = static_cast<uint8_t>(profile.payload_budget >> 8);
  output[4] = profile.max_nodes;
  const uint16_t fields[]{profile.provided, profile.required};
  for (size_t i = 0; i < 2; ++i) {
    output[5 + i * 2] = static_cast<uint8_t>(fields[i]);
    output[6 + i * 2] = static_cast<uint8_t>(fields[i] >> 8);
  }
  return true;
}
inline bool decode(const uint8_t *input, size_t length, Profile &profile) {
  if (input == nullptr || length != PROFILE_WIRE_SIZE)
    return false;
  Profile candidate{input[0],
                    input[1],
                    static_cast<uint16_t>(input[2] | (uint16_t(input[3]) << 8)),
                    input[4],
                    static_cast<uint16_t>(input[5] | (uint16_t(input[6]) << 8)),
                    static_cast<uint16_t>(input[7] | (uint16_t(input[8]) << 8))};
  if (!valid(candidate))
    return false;
  profile = candidate;
  return true;
}

}  // namespace mesh_protocol
