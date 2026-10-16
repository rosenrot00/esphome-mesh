#include "mesh_endpoint.h"

namespace mesh_ip {
namespace {
constexpr uint8_t VERSION = 1;

uint32_t read32le(const uint8_t *p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
uint32_t read32be(const uint8_t *p) {
  return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]);
}
uint64_t read64le(const uint8_t *p) { return uint64_t(read32le(p)) | uint64_t(read32le(p + 4)) << 32; }
void write32le(uint8_t *p, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    p[i] = uint8_t(value >> (8 * i));
}
void write32be(uint8_t *p, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    p[i] = uint8_t(value >> (8 * (3 - i)));
}
void write64le(uint8_t *p, uint64_t value) {
  write32le(p, uint32_t(value));
  write32le(p + 4, uint32_t(value >> 32));
}
bool unicast(uint32_t address) {
  const uint32_t first = address >> 24;
  return first != 0 && first != 127 && first < 224;
}
bool valid(const EndpointAdvertisement &advertisement) {
  switch (advertisement.mode) {
    case EndpointMode::NONE:
    case EndpointMode::NATIVE:
    case EndpointMode::QUIET:
      return advertisement.remaining_seconds == 0;
    case EndpointMode::MESH:
      break;
    default:
      return false;
  }
  if (advertisement.nonce == 0 || advertisement.session == 0 || advertisement.lease_id == 0 ||
      advertisement.remaining_seconds == 0 || !unicast(advertisement.address) || !unicast(advertisement.router) ||
      !unicast(advertisement.server))
    return false;
  // Match the DHCP client's supported LAN shape: /1 through /30, with valid
  // distinct host addresses for the client and its on-link default router.
  const uint32_t inverse = ~advertisement.netmask;
  if (advertisement.netmask == 0 || inverse < 3 || (inverse & (inverse + 1)) != 0 ||
      (advertisement.address & inverse) == 0 || (advertisement.address & inverse) == inverse ||
      (advertisement.router & advertisement.netmask) != (advertisement.address & advertisement.netmask) ||
      advertisement.router == advertisement.address || (advertisement.router & inverse) == 0 ||
      (advertisement.router & inverse) == inverse)
    return false;
  return true;
}
}  // namespace

bool encode_endpoint_challenge(uint64_t nonce, uint8_t *output, size_t capacity, size_t &written) {
  written = 0;
  if (nonce == 0 || output == nullptr || capacity < ENDPOINT_CHALLENGE_SIZE)
    return false;
  output[0] = VERSION;
  output[1] = ENDPOINT_CHALLENGE_CONTROL;
  write64le(output + 2, nonce);
  written = ENDPOINT_CHALLENGE_SIZE;
  return true;
}

bool decode_endpoint_challenge(const uint8_t *data, size_t length, uint64_t &nonce) {
  if (data == nullptr || length != ENDPOINT_CHALLENGE_SIZE || data[0] != VERSION ||
      data[1] != ENDPOINT_CHALLENGE_CONTROL)
    return false;
  const uint64_t decoded = read64le(data + 2);
  if (decoded == 0)
    return false;
  nonce = decoded;
  return true;
}

bool encode_endpoint_advertisement(const EndpointAdvertisement &advertisement, uint8_t *output, size_t capacity,
                                   size_t &written) {
  written = 0;
  if (output == nullptr || capacity < ENDPOINT_RESPONSE_SIZE || !valid(advertisement))
    return false;
  output[0] = VERSION;
  output[1] = ENDPOINT_RESPONSE_CONTROL;
  write64le(output + 2, advertisement.nonce);
  write64le(output + 10, advertisement.session);
  write32le(output + 18, advertisement.lease_id);
  output[22] = uint8_t(advertisement.mode);
  write32be(output + 23, advertisement.address);
  write32be(output + 27, advertisement.netmask);
  write32be(output + 31, advertisement.router);
  write32be(output + 35, advertisement.server);
  write32le(output + 39, advertisement.remaining_seconds);
  written = ENDPOINT_RESPONSE_SIZE;
  return true;
}

bool decode_endpoint_advertisement(const uint8_t *data, size_t length, EndpointAdvertisement &advertisement) {
  if (data == nullptr || length != ENDPOINT_RESPONSE_SIZE || data[0] != VERSION || data[1] != ENDPOINT_RESPONSE_CONTROL)
    return false;
  EndpointAdvertisement decoded;
  decoded.nonce = read64le(data + 2);
  decoded.session = read64le(data + 10);
  decoded.lease_id = read32le(data + 18);
  decoded.mode = static_cast<EndpointMode>(data[22]);
  decoded.address = read32be(data + 23);
  decoded.netmask = read32be(data + 27);
  decoded.router = read32be(data + 31);
  decoded.server = read32be(data + 35);
  decoded.remaining_seconds = read32le(data + 39);
  if (!valid(decoded))
    return false;
  advertisement = decoded;
  return true;
}

bool witness_matches_subject(const LeaseWitness &witness, WitnessIdentityMode mode, uint64_t current_subject_session) {
  if (witness.node_id == 0 || witness.node_id > mesh_limits::MAX_NODES || witness.lease_id == 0 ||
      witness.remaining_seconds == 0 || !unicast(witness.address))
    return false;
  if (mode == WitnessIdentityMode::LEGACY)
    return witness.subject_session == 0 && current_subject_session == 0;
  return mode == WitnessIdentityMode::SESSION_BOUND && current_subject_session != 0 &&
         witness.subject_session == current_subject_session;
}

bool encode_lease_witness(const LeaseWitness &witness, WitnessIdentityMode mode, uint8_t *output, size_t capacity,
                          size_t &written) {
  written = 0;
  const size_t size =
      mode == WitnessIdentityMode::SESSION_BOUND ? SESSION_LEASE_WITNESS_SIZE : LEGACY_LEASE_WITNESS_SIZE;
  if (output == nullptr || capacity < size || !witness_matches_subject(witness, mode, witness.subject_session))
    return false;
  output[0] = mode == WitnessIdentityMode::SESSION_BOUND ? 2 : 1;
  output[1] = LEASE_WITNESS_CONTROL;
  output[2] = witness.node_id;
  write32be(output + 3, witness.address);
  write32le(output + 7, witness.lease_id);
  write32le(output + 11, witness.remaining_seconds);
  if (mode == WitnessIdentityMode::SESSION_BOUND)
    write64le(output + 15, witness.subject_session);
  written = size;
  return true;
}

bool decode_lease_witness(const uint8_t *data, size_t length, WitnessIdentityMode mode, LeaseWitness &witness) {
  const bool session_bound = mode == WitnessIdentityMode::SESSION_BOUND;
  if (data == nullptr || length != (session_bound ? SESSION_LEASE_WITNESS_SIZE : LEGACY_LEASE_WITNESS_SIZE) ||
      data[0] != (session_bound ? 2 : 1) || data[1] != LEASE_WITNESS_CONTROL)
    return false;
  LeaseWitness decoded;
  decoded.node_id = data[2];
  decoded.address = read32be(data + 3);
  decoded.lease_id = read32le(data + 7);
  decoded.remaining_seconds = read32le(data + 11);
  if (session_bound)
    decoded.subject_session = read64le(data + 15);
  if (!witness_matches_subject(decoded, mode, decoded.subject_session))
    return false;
  witness = decoded;
  return true;
}

bool ChallengeRegistry::begin(uint8_t node, uint64_t random_nonce, uint32_t now) {
  if (node == 0 || node > mesh_limits::MAX_NODES || random_nonce == 0)
    return false;
  auto &challenge = this->challenges_[node - 1];
  if (challenge.pending && uint32_t(now - challenge.started) < ENDPOINT_CHALLENGE_LIFETIME_MS)
    return false;
  challenge.nonce = random_nonce;
  challenge.started = now;
  challenge.pending = true;
  return true;
}

bool ChallengeRegistry::consume(uint8_t node, uint64_t nonce, uint32_t now, uint32_t &age_ms) {
  age_ms = 0;
  if (node == 0 || node > mesh_limits::MAX_NODES || nonce == 0)
    return false;
  auto &challenge = this->challenges_[node - 1];
  if (!challenge.pending)
    return false;
  const uint32_t age = now - challenge.started;
  if (age >= ENDPOINT_CHALLENGE_LIFETIME_MS) {
    challenge.pending = false;
    return false;
  }
  if (nonce != challenge.nonce)
    return false;
  challenge.pending = false;
  age_ms = age;
  return true;
}

void ChallengeRegistry::reset_peer(uint8_t node) {
  if (node == 0 || node > mesh_limits::MAX_NODES)
    return;
  this->challenges_[node - 1] = Challenge{};
}

bool ChallengeRegistry::cancel(uint8_t node, uint64_t nonce) {
  if (node == 0 || node > mesh_limits::MAX_NODES || nonce == 0)
    return false;
  auto &challenge = this->challenges_[node - 1];
  if (!challenge.pending || challenge.nonce != nonce)
    return false;
  challenge.pending = false;
  return true;
}

uint32_t ChallengeRegistry::freshness_budget(uint32_t remaining_seconds, uint32_t age_ms) {
  const uint64_t remaining_ms = uint64_t(remaining_seconds) * 1000;
  const uint64_t bounded = remaining_ms < ENDPOINT_MAX_FRESHNESS_MS ? remaining_ms : ENDPOINT_MAX_FRESHNESS_MS;
  return bounded > age_ms ? uint32_t(bounded - age_ms) : 0;
}

}  // namespace mesh_ip
