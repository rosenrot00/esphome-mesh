#pragma once

#include "mesh_limits.h"

#include <cstddef>
#include <cstdint>

namespace mesh_ip {

constexpr uint8_t ENDPOINT_CHALLENGE_CONTROL = 10;
constexpr uint8_t ENDPOINT_RESPONSE_CONTROL = 11;
constexpr uint8_t LEASE_WITNESS_CONTROL = 12;
constexpr size_t ENDPOINT_CHALLENGE_SIZE = 10;
constexpr size_t ENDPOINT_RESPONSE_SIZE = 43;
constexpr size_t LEGACY_LEASE_WITNESS_SIZE = 15;
constexpr size_t SESSION_LEASE_WITNESS_SIZE = 23;
constexpr uint32_t ENDPOINT_CHALLENGE_LIFETIME_MS = 2000;
constexpr uint32_t ENDPOINT_MAX_FRESHNESS_MS = 5000;

enum class EndpointMode : uint8_t { NONE = 0, MESH = 1, NATIVE = 2, QUIET = 3 };

// Endpoint identity and its DHCP lease belong to the client, independently of
// its current route. Addresses use numeric network order, as in DhcpLease.
struct EndpointAdvertisement {
  uint64_t nonce{0};
  uint64_t session{0};
  uint32_t lease_id{0};
  EndpointMode mode{EndpointMode::NONE};
  uint32_t address{0}, netmask{0}, router{0}, server{0};
  uint32_t remaining_seconds{0};
};

bool encode_endpoint_challenge(uint64_t nonce, uint8_t *output, size_t capacity, size_t &written);
bool decode_endpoint_challenge(const uint8_t *data, size_t length, uint64_t &nonce);
bool encode_endpoint_advertisement(const EndpointAdvertisement &advertisement, uint8_t *output, size_t capacity,
                                   size_t &written);
bool decode_endpoint_advertisement(const uint8_t *data, size_t length, EndpointAdvertisement &advertisement);

// A gateway relays lease evidence about a third node. Its frame's own source
// and destination sessions cannot bind that subject to the current slot owner.
// Session-bound mode must never fall back when the subject is not yet admitted.
enum class WitnessIdentityMode : uint8_t { LEGACY, SESSION_BOUND };
struct LeaseWitness {
  uint8_t node_id{0};
  uint32_t address{0}, lease_id{0}, remaining_seconds{0};
  uint64_t subject_session{0};
};
bool encode_lease_witness(const LeaseWitness &witness, WitnessIdentityMode mode, uint8_t *output, size_t capacity,
                          size_t &written);
bool decode_lease_witness(const uint8_t *data, size_t length, WitnessIdentityMode mode, LeaseWitness &witness);
bool witness_matches_subject(const LeaseWitness &witness, WitnessIdentityMode mode, uint64_t current_subject_session);

// Allocation-free, one-use freshness proofs for node IDs 1..16. The caller
// authenticates the mesh source and supplies a fresh random nonzero nonce.
// Serialized access and intervals shorter than one uint32_t clock wrap are
// required. A live challenge cannot be replaced or extended by begin().
class ChallengeRegistry {
 public:
  bool begin(uint8_t node, uint64_t random_nonce, uint32_t now);
  // Queue admission failed: no challenge was sent, so release only this nonce.
  bool cancel(uint8_t node, uint64_t nonce);
  // A changed authenticated owner must never inherit an old slot's proof.
  // Invalid IDs are ignored; challenges for other peers remain live.
  void reset_peer(uint8_t node);
  bool consume(uint8_t node, uint64_t nonce, uint32_t now, uint32_t &age_ms);
  // Deduct the entire challenge round-trip from the advertised lease budget,
  // conservatively bounding even very long or infinite DHCP leases to 5 s.
  static uint32_t freshness_budget(uint32_t remaining_seconds, uint32_t age_ms);

 private:
  struct Challenge {
    uint64_t nonce{0};
    uint32_t started{0};
    bool pending{false};
  };
  Challenge challenges_[mesh_limits::MAX_NODES]{};
};

}  // namespace mesh_ip
