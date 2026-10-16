#pragma once

#include "mesh_limits.h"

#include "mesh_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>

// Group membership is one security domain: possession of the network key
// authorizes every identity. Pair keys do not isolate a compromised member.
// No certificates, forward secrecy or independently trusted identities.
namespace mesh_auto {

using Mac = std::array<uint8_t, 6>;
using Key32 = std::array<uint8_t, 32>;
using Key16 = std::array<uint8_t, 16>;
using BootNonce = std::array<uint8_t, 16>;
using NetworkId = std::array<uint8_t, 8>;
constexpr uint8_t kGatewayCapable = 1;
constexpr uint8_t kPinnedNodeId = 2;
constexpr uint8_t kNativeUplink = 4;
constexpr size_t kDiscoveryWireSize = 106 + mesh_protocol::PROFILE_WIRE_SIZE;
constexpr size_t kMaxDiscoveryWireSize = kDiscoveryWireSize;
constexpr size_t kGroupEnvelopeHeaderSize = 31;
constexpr size_t kGroupEnvelopeOverhead = kGroupEnvelopeHeaderSize + 16;
constexpr size_t kMaxGroupEnvelopeSize = 128;
constexpr size_t kMaxGroupPayloadSize = kMaxGroupEnvelopeSize - kGroupEnvelopeOverhead;
constexpr size_t kMaxAuthenticatedPeers = mesh_limits::MAX_PEERS;
constexpr uint32_t kHelloIntervalMs = 1000;
constexpr uint32_t kChallengeTimeoutMs = 3000;
constexpr uint32_t kHandshakeRetryMs = 250;
constexpr uint32_t kReauthenticateMs = 5000;
constexpr uint32_t kAuthenticationLifetimeMs = 15000;

struct Crypto {
  void *context{nullptr};
  bool (*random)(void *, uint8_t *, size_t){nullptr};
  bool (*hmac_sha256)(void *, const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                      uint8_t output[32]){nullptr};
};

// The HMAC implementation is platform-owned. HKDF follows RFC 5869. These
// helpers have no SDK dependency; all supported outputs are <=32 bytes.
bool hkdf_extract(const Crypto &, const uint8_t *salt, size_t salt_length, const uint8_t *ikm, size_t ikm_length,
                  Key32 &prk);
bool hkdf_expand(const Crypto &, const Key32 &prk, const uint8_t *info, size_t info_length, uint8_t *output,
                 size_t output_length);
bool valid_mac(const Mac &mac);
bool is_discovery_packet(const uint8_t *data, size_t length);

struct PeerIdentity {
  Mac mac{};
  BootNonce boot_nonce{};
  uint8_t node_id{0};  // 0 is an authenticated, not-yet-assigned identity.
  uint8_t flags{0};
  mesh_protocol::Profile protocol{};
};

struct DiscoveryCallbacks {
  void *context{nullptr};
  // A true return accepts/copies the complete message; not a delivery ACK.
  // All messages may travel over native broadcast: signed target+boot fields
  // restrict responses to their intended recipient.
  bool (*send)(void *, const Mac &destination, const uint8_t *, size_t){nullptr};
  void (*authenticated)(void *, const PeerIdentity &){nullptr};
  void (*revoked)(void *, const Mac &){nullptr};
};

// Serialized by the integration worker; callbacks must not re-enter this
// object. Bounded per-radio-neighbor state, no allocations. The identity/ID
// allocator remains separate and sees only challenge-verified claims.
class AuthDiscovery {
 public:
  bool configure(const Key32 &network_key, const Mac &local_mac, uint8_t node_id, uint8_t flags, const Crypto &crypto,
                 const DiscoveryCallbacks &callbacks, const mesh_protocol::Profile &protocol = {});
  bool begin(uint32_t now_ms);
  // Expiry always follows wall-clock time. A closed radio ownership phase
  // suppresses new discovery signing/transmission without extending proofs.
  void tick(uint32_t now_ms, bool allow_transmit = true);
  bool receive(const Mac &actual_source, const uint8_t *data, size_t length, uint32_t now_ms);
  bool set_local_identity(uint8_t node_id, uint8_t flags);
  bool derive_network_key(const char *domain, Key16 &output) const;
  bool derive_session_key(const PeerIdentity &peer, const char *domain, Key16 &output) const;
  bool derive_pmk(Key16 &output) const;
  // Static MAC-only derivation is retained for explicit/manual provisioning.
  // Automatic peers must use the boot-bound session derivation below.
  bool derive_pair_lmk(const Mac &peer, Key16 &output) const;
  bool derive_session_lmk(const PeerIdentity &peer, Key16 &output) const;
  // Network-wide opaque ownership epoch for a proven MAC+boot identity. This
  // does not grant membership or authenticate an origin independently of the
  // group key. Compact IDs are deliberately excluded, so every member derives
  // the same value. Zero is reserved for legacy/absent sessions.
  bool identity_session_tag(const Mac &identity, const BootNonce &boot, uint64_t &output) const;
  // For the separate identity gossip protocol. This key is domain separated
  // from discovery and link keys. Freshness must be checked by that protocol;
  // a valid group tag alone never grants admission or proves liveness.
  bool sign_group(const uint8_t *data, size_t length, Key16 &tag) const;
  bool verify_group(const uint8_t *data, size_t length, const Key16 &tag) const;
  // Authenticated neighbor management envelope (MA1 subtype0x10), binding
  // immediate MAC+boot+sequence. open rejects duplicates and accepts at most
  // 63 packets of reordering. Its payload view borrows the input wire buffer.
  bool seal_group(const uint8_t *payload, size_t length, uint8_t *output, size_t capacity, size_t &written);
  bool open_group(const Mac &actual_source, const uint8_t *wire, size_t length, uint32_t now_ms,
                  const uint8_t *&payload, size_t &payload_length);
  const PeerIdentity &local_identity() const { return local_; }
  const BootNonce &boot_nonce() const { return local_.boot_nonce; }
  const NetworkId &network_id() const { return network_id_; }
  bool authenticated(const Mac &peer, uint32_t now_ms) const;
  size_t authenticated_count(uint32_t now_ms) const;
  bool ready() const { return begun_; }
  uint32_t incompatible_count() const { return this->incompatible_count_; }

 private:
  enum class Kind : uint8_t { HELLO = 1, CHALLENGE = 2, RESPONSE = 3, ACK = 4 };
  struct Message {
    Kind kind{Kind::HELLO};
    PeerIdentity source{};
    Mac destination{};
    BootNonce destination_boot{};
    BootNonce challenge{};
    BootNonce reply_challenge{};
  };
  struct Peer {
    bool used{false}, verified{false}, outgoing{false}, incoming{false};
    bool outgoing_complete{false};
    PeerIdentity identity{}, outgoing_identity{}, incoming_identity{};
    BootNonce out_challenge{}, out_reply{}, in_challenge{}, in_reply{};
    uint32_t verified_at{0}, touched_at{0}, out_at{0}, in_at{0};
    uint32_t out_sent_at{0}, in_sent_at{0};
    uint32_t group_highest{0};
    uint64_t group_seen{0};
  };
  bool decode_(const Mac &, const uint8_t *, size_t, Message &) const;
  bool send_(Kind, const PeerIdentity &, const BootNonce &, const BootNonce &);
  bool hello_();
  bool challenge_(Peer &, const PeerIdentity &, uint32_t);
  bool random_nonce_(BootNonce &) const;
  bool derive_(const char *label, const uint8_t *extra, size_t extra_length, uint8_t *output,
               size_t output_length) const;
  Peer *peer_(const Mac &, uint32_t, bool create);
  void verify_(Peer &, const PeerIdentity &, uint32_t);
  Crypto crypto_{};
  DiscoveryCallbacks callbacks_{};
  PeerIdentity local_{};
  NetworkId network_id_{};
  Key32 prk_{}, discovery_key_{}, group_key_{};
  Peer peers_[kMaxAuthenticatedPeers]{};
  uint32_t last_hello_{0};
  uint32_t group_sequence_{0};
  uint32_t incompatible_count_{0};
  bool configured_{false}, begun_{false}, hello_due_{false};
};

}  // namespace mesh_auto
