#include "mesh_auto_security.h"

#include <algorithm>
#include <cstring>

namespace mesh_auto {
namespace {
constexpr Mac kBroadcast{{255, 255, 255, 255, 255, 255}};
constexpr uint8_t kKnownFlags = kGatewayCapable | kPinnedNodeId | kNativeUplink;
constexpr char kSalt[] = "ESPHome mesh automatic membership v1";
constexpr size_t kSignedSize = kDiscoveryWireSize - 16;
bool nonzero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0;
  for (size_t i = 0; i < length; ++i)
    combined |= bytes[i];
  return combined != 0;
}
bool equal(const uint8_t *a, const uint8_t *b, size_t length) {
  uint8_t difference = 0;
  for (size_t i = 0; i < length; ++i)
    difference |= a[i] ^ b[i];
  return difference == 0;
}
void erase(uint8_t *bytes, size_t length) {
  volatile uint8_t *p = bytes;
  while (length-- != 0)
    *p++ = 0;
}
bool same_identity(const PeerIdentity &a, const PeerIdentity &b) {
  return a.mac == b.mac && a.boot_nonce == b.boot_nonce && a.node_id == b.node_id && a.flags == b.flags &&
         mesh_protocol::same(a.protocol, b.protocol);
}
bool valid_identity(uint8_t node, uint8_t flags) {
  return node <= mesh_limits::MAX_NODES && (flags & ~kKnownFlags) == 0 && ((flags & kPinnedNodeId) == 0 || node != 0) &&
         ((flags & kNativeUplink) == 0 || (flags & kGatewayCapable) != 0);
}
}  // namespace

bool hkdf_extract(const Crypto &crypto, const uint8_t *salt, size_t salt_length, const uint8_t *ikm, size_t ikm_length,
                  Key32 &prk) {
  if (crypto.hmac_sha256 == nullptr || (ikm_length && ikm == nullptr) || (salt_length && salt == nullptr))
    return false;
  const Key32 zeros{};
  if (salt_length == 0) {
    salt = zeros.data();
    salt_length = zeros.size();
  }
  if (crypto.hmac_sha256(crypto.context, salt, salt_length, ikm, ikm_length, prk.data()))
    return true;
  prk.fill(0);
  return false;
}

bool hkdf_expand(const Crypto &crypto, const Key32 &prk, const uint8_t *info, size_t info_length, uint8_t *output,
                 size_t output_length) {
  // This implementation deliberately exposes one RFC 5869 block only.
  if (crypto.hmac_sha256 == nullptr || output == nullptr || output_length == 0 || output_length > 32 ||
      info_length > 127 || (info_length && info == nullptr))
    return false;
  uint8_t input[128]{};
  if (info_length)
    std::memcpy(input, info, info_length);
  input[info_length] = 1;
  Key32 block{};
  const bool ok = crypto.hmac_sha256(crypto.context, prk.data(), prk.size(), input, info_length + 1, block.data());
  if (ok)
    std::memcpy(output, block.data(), output_length);
  else
    erase(output, output_length);
  erase(block.data(), block.size());
  return ok;
}

bool valid_mac(const Mac &mac) { return (mac[0] & 1) == 0 && nonzero(mac.data(), mac.size()); }
bool is_discovery_packet(const uint8_t *data, size_t length) {
  return data != nullptr && length == kDiscoveryWireSize && data[0] == 'M' && data[1] == 'A' && data[2] == 4 &&
         data[3] >= 1 && data[3] <= 4;
}

bool AuthDiscovery::configure(const Key32 &network_key, const Mac &local_mac, uint8_t node_id, uint8_t flags,
                              const Crypto &crypto, const DiscoveryCallbacks &callbacks,
                              const mesh_protocol::Profile &protocol) {
  // Reconfiguration is explicit, before use, and discards all prior admission.
  if (begun_ || (protocol.max_nodes != mesh_limits::MAX_NODES || !mesh_protocol::valid(protocol)) ||
      !valid_mac(local_mac) || !valid_identity(node_id, flags) || crypto.random == nullptr ||
      crypto.hmac_sha256 == nullptr || callbacks.send == nullptr)
    return false;
  configured_ = false;
  crypto_ = crypto;
  callbacks_ = callbacks;
  local_ = {};
  local_.mac = local_mac;
  local_.node_id = node_id;
  local_.flags = flags;
  local_.protocol = protocol;
  for (auto &peer : peers_)
    peer = {};
  if (!hkdf_extract(crypto_, reinterpret_cast<const uint8_t *>(kSalt), sizeof(kSalt) - 1, network_key.data(),
                    network_key.size(), prk_) ||
      !derive_("network-id", nullptr, 0, network_id_.data(), network_id_.size()) ||
      !derive_("discovery-auth", nullptr, 0, discovery_key_.data(), discovery_key_.size()) ||
      !derive_("membership-auth", nullptr, 0, group_key_.data(), group_key_.size())) {
    erase(prk_.data(), prk_.size());
    erase(discovery_key_.data(), discovery_key_.size());
    erase(group_key_.data(), group_key_.size());
    network_id_.fill(0);
    return false;
  }
  configured_ = true;
  return true;
}

bool AuthDiscovery::derive_(const char *label, const uint8_t *extra, size_t extra_length, uint8_t *output,
                            size_t output_length) const {
  constexpr char prefix[] = "ESPHome-mesh-v1/";
  const size_t label_length = std::strlen(label);
  if (label_length + extra_length + sizeof(prefix) > 96 || (extra_length && extra == nullptr))
    return false;
  uint8_t info[96]{};
  size_t used = sizeof(prefix) - 1;
  std::memcpy(info, prefix, used);
  std::memcpy(info + used, label, label_length);
  used += label_length;
  info[used++] = 0;  // Unambiguous label/identity boundary.
  if (extra_length)
    std::memcpy(info + used, extra, extra_length);
  return hkdf_expand(crypto_, prk_, info, used + extra_length, output, output_length);
}

bool AuthDiscovery::derive_pmk(Key16 &output) const { return this->derive_network_key("espnow-pmk", output); }

bool AuthDiscovery::derive_network_key(const char *domain, Key16 &output) const {
  if (!configured_ || domain == nullptr || domain[0] == 0) {
    output.fill(0);
    return false;
  }
  return derive_(domain, network_id_.data(), network_id_.size(), output.data(), output.size());
}

bool AuthDiscovery::derive_pair_lmk(const Mac &peer, Key16 &output) const {
  if (!configured_ || !valid_mac(peer) || peer == local_.mac) {
    output.fill(0);
    return false;
  }
  uint8_t extra[20]{};
  std::memcpy(extra, network_id_.data(), network_id_.size());
  const Mac &first = peer < local_.mac ? peer : local_.mac;
  const Mac &second = peer < local_.mac ? local_.mac : peer;
  std::memcpy(extra + 8, first.data(), first.size());
  std::memcpy(extra + 14, second.data(), second.size());
  return derive_("espnow-link", extra, sizeof(extra), output.data(), output.size());
}

bool AuthDiscovery::derive_session_lmk(const PeerIdentity &peer, Key16 &output) const {
  return this->derive_session_key(peer, "espnow-session", output);
}

bool AuthDiscovery::derive_session_key(const PeerIdentity &peer, const char *domain, Key16 &output) const {
  if (domain == nullptr || domain[0] == 0 || !begun_ || !valid_mac(peer.mac) || peer.mac == local_.mac ||
      !nonzero(peer.boot_nonce.data(), peer.boot_nonce.size())) {
    output.fill(0);
    return false;
  }
  uint8_t extra[52]{};
  std::memcpy(extra, network_id_.data(), network_id_.size());
  const PeerIdentity &first = peer.mac < local_.mac ? peer : local_;
  const PeerIdentity &second = peer.mac < local_.mac ? local_ : peer;
  std::memcpy(extra + 8, first.mac.data(), 6);
  std::memcpy(extra + 14, first.boot_nonce.data(), 16);
  std::memcpy(extra + 30, second.mac.data(), 6);
  std::memcpy(extra + 36, second.boot_nonce.data(), 16);
  return derive_(domain, extra, sizeof(extra), output.data(), output.size());
}

bool AuthDiscovery::identity_session_tag(const Mac &identity, const BootNonce &boot, uint64_t &output) const {
  output = 0;
  if (!configured_ || !valid_mac(identity) || !nonzero(boot.data(), boot.size()))
    return false;
  uint8_t extra[31]{};
  std::memcpy(extra, network_id_.data(), network_id_.size());
  std::memcpy(extra + 8, identity.data(), identity.size());
  std::memcpy(extra + 14, boot.data(), boot.size());
  // The retry byte is always present, including attempt zero. Every node must
  // deterministically skip the reserved zero value using the same identity.
  std::array<uint8_t, 8> bytes{};
  for (uint16_t attempt = 0; attempt < 256; ++attempt) {
    extra[30] = static_cast<uint8_t>(attempt);
    if (!derive_("identity-session", extra, sizeof(extra), bytes.data(), bytes.size()))
      return false;
    uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i)
      value |= static_cast<uint64_t>(bytes[i]) << (8 * i);  // Canonical little endian.
    if (value != 0) {
      output = value;
      return true;
    }
  }
  return false;  // A broken crypto provider cannot cause an unbounded loop.
}

bool AuthDiscovery::sign_group(const uint8_t *data, size_t length, Key16 &tag) const {
  if (!configured_ || (length && data == nullptr)) {
    tag.fill(0);
    return false;
  }
  Key32 full{};
  const bool ok = crypto_.hmac_sha256(crypto_.context, group_key_.data(), group_key_.size(), data, length, full.data());
  if (ok)
    std::copy_n(full.begin(), tag.size(), tag.begin());
  else
    tag.fill(0);
  erase(full.data(), full.size());
  return ok;
}

bool AuthDiscovery::verify_group(const uint8_t *data, size_t length, const Key16 &tag) const {
  Key16 expected{};
  return sign_group(data, length, expected) && equal(expected.data(), tag.data(), tag.size());
}

bool AuthDiscovery::seal_group(const uint8_t *payload, size_t length, uint8_t *output, size_t capacity,
                               size_t &written) {
  written = 0;
  if (!begun_ || payload == nullptr || length == 0 || length > kMaxGroupPayloadSize || output == nullptr ||
      capacity < length + kGroupEnvelopeOverhead)
    return false;
  const size_t signed_size = kGroupEnvelopeHeaderSize + length;
  // Move first, so an integration may safely wrap an in-place payload.
  std::memmove(output + kGroupEnvelopeHeaderSize, payload, length);
  output[0] = 'M';
  output[1] = 'A';
  output[2] = 1;
  output[3] = 0x10;
  std::memcpy(output + 4, local_.mac.data(), 6);
  std::memcpy(output + 10, local_.boot_nonce.data(), 16);
  ++group_sequence_;
  if (group_sequence_ == 0)
    ++group_sequence_;
  for (size_t i = 0; i < 4; ++i)
    output[26 + i] = static_cast<uint8_t>(group_sequence_ >> (i * 8));
  output[30] = static_cast<uint8_t>(length);
  Key16 tag{};
  if (!sign_group(output, signed_size, tag))
    return false;
  std::memcpy(output + signed_size, tag.data(), tag.size());
  written = signed_size + tag.size();
  return true;
}

bool AuthDiscovery::open_group(const Mac &actual_source, const uint8_t *wire, size_t length, uint32_t now,
                               const uint8_t *&payload, size_t &payload_length) {
  payload = nullptr;
  payload_length = 0;
  if (!begun_ || wire == nullptr || length <= kGroupEnvelopeOverhead || length > kMaxGroupEnvelopeSize ||
      wire[0] != 'M' || wire[1] != 'A' || wire[2] != 1 || wire[3] != 0x10 ||
      wire[30] != length - kGroupEnvelopeOverhead || actual_source == local_.mac ||
      !equal(actual_source.data(), wire + 4, actual_source.size()))
    return false;
  Peer *peer = peer_(actual_source, now, false);
  if (peer == nullptr || !peer->verified || now - peer->verified_at >= kAuthenticationLifetimeMs ||
      !equal(peer->identity.boot_nonce.data(), wire + 10, peer->identity.boot_nonce.size()))
    return false;
  const uint32_t sequence =
      uint32_t(wire[26]) | (uint32_t(wire[27]) << 8) | (uint32_t(wire[28]) << 16) | (uint32_t(wire[29]) << 24);
  if (sequence == 0)
    return false;
  Key16 tag{};
  std::memcpy(tag.data(), wire + length - tag.size(), tag.size());
  if (!verify_group(wire, length - tag.size(), tag))
    return false;
  // Replay state changes only after cryptographic verification. A fresh boot
  // proof resets this window; periodic same-boot reauthentication never does.
  if (peer->group_seen == 0) {
    peer->group_highest = sequence;
    peer->group_seen = 1;
  } else {
    const int32_t forward = static_cast<int32_t>(sequence - peer->group_highest);
    if (forward > 0) {
      peer->group_seen = forward >= 64 ? 1 : (peer->group_seen << forward) | 1;
      peer->group_highest = sequence;
    } else {
      const uint32_t behind = peer->group_highest - sequence;
      if (behind >= 64 || (peer->group_seen & (uint64_t(1) << behind)) != 0)
        return false;
      peer->group_seen |= uint64_t(1) << behind;
    }
  }
  payload = wire + kGroupEnvelopeHeaderSize;
  payload_length = wire[30];
  return true;
}

bool AuthDiscovery::random_nonce_(BootNonce &output) const {
  if (!crypto_.random(crypto_.context, output.data(), output.size()) || !nonzero(output.data(), output.size())) {
    output.fill(0);
    return false;
  }
  return true;
}

bool AuthDiscovery::begin(uint32_t now) {
  if (!configured_ || begun_ || !random_nonce_(local_.boot_nonce))
    return false;
  begun_ = true;
  hello_due_ = true;
  last_hello_ = now;
  // Radio start may still be pending. A rejected send is retried by tick().
  if (hello_()) {
    hello_due_ = false;
    last_hello_ = now;
  }
  return true;
}

bool AuthDiscovery::set_local_identity(uint8_t node_id, uint8_t flags) {
  if (!valid_identity(node_id, flags))
    return false;
  if (local_.node_id == node_id && local_.flags == flags)
    return true;
  local_.node_id = node_id;
  local_.flags = flags;
  hello_due_ = true;
  for (auto &peer : peers_) {
    peer.outgoing = false;
    peer.incoming = false;
  }
  return true;
}

bool AuthDiscovery::send_(Kind kind, const PeerIdentity &destination, const BootNonce &challenge,
                          const BootNonce &reply) {
  uint8_t wire[kDiscoveryWireSize]{};
  wire[0] = 'M';
  wire[1] = 'A';
  wire[2] = 4;
  wire[3] = static_cast<uint8_t>(kind);
  wire[4] = local_.flags;
  wire[5] = local_.node_id;
  std::memcpy(wire + 6, network_id_.data(), 8);
  std::memcpy(wire + 14, local_.mac.data(), 6);
  std::memcpy(wire + 20, destination.mac.data(), 6);
  std::memcpy(wire + 26, local_.boot_nonce.data(), 16);
  std::memcpy(wire + 42, destination.boot_nonce.data(), 16);
  std::memcpy(wire + 58, challenge.data(), 16);
  std::memcpy(wire + 74, reply.data(), 16);
  if (!mesh_protocol::encode(local_.protocol, wire + 90, mesh_protocol::PROFILE_WIRE_SIZE))
    return false;
  Key32 tag{};
  if (!crypto_.hmac_sha256(crypto_.context, discovery_key_.data(), discovery_key_.size(), wire, kSignedSize,
                           tag.data())) {
    erase(tag.data(), tag.size());
    return false;
  }
  std::memcpy(wire + kSignedSize, tag.data(), 16);
  erase(tag.data(), tag.size());
  return callbacks_.send(callbacks_.context, destination.mac, wire, sizeof(wire));
}

bool AuthDiscovery::hello_() {
  PeerIdentity destination{};
  destination.mac = kBroadcast;
  return send_(Kind::HELLO, destination, {}, {});
}

bool AuthDiscovery::decode_(const Mac &actual, const uint8_t *wire, size_t length, Message &message) const {
  if (!begun_ || length != kDiscoveryWireSize || !is_discovery_packet(wire, length) || wire[3] < 1 || wire[3] > 4 ||
      !valid_identity(wire[5], wire[4]) || !equal(wire + 6, network_id_.data(), network_id_.size()))
    return false;
  message = {};
  message.kind = static_cast<Kind>(wire[3]);
  message.source.flags = wire[4];
  message.source.node_id = wire[5];
  std::memcpy(message.source.mac.data(), wire + 14, 6);
  if (!valid_mac(message.source.mac) || message.source.mac != actual || actual == local_.mac)
    return false;
  std::memcpy(message.destination.data(), wire + 20, 6);
  std::memcpy(message.source.boot_nonce.data(), wire + 26, 16);
  std::memcpy(message.destination_boot.data(), wire + 42, 16);
  std::memcpy(message.challenge.data(), wire + 58, 16);
  std::memcpy(message.reply_challenge.data(), wire + 74, 16);
  if (!mesh_protocol::decode(wire + 90, mesh_protocol::PROFILE_WIRE_SIZE, message.source.protocol) ||
      message.source.node_id > message.source.protocol.max_nodes)
    return false;
  if (!nonzero(message.source.boot_nonce.data(), 16))
    return false;
  if (message.kind == Kind::HELLO) {
    if (message.destination != kBroadcast || nonzero(message.destination_boot.data(), 16) ||
        nonzero(message.challenge.data(), 16) || nonzero(message.reply_challenge.data(), 16))
      return false;
  } else {
    if (message.destination != local_.mac || message.destination_boot != local_.boot_nonce ||
        !nonzero(message.challenge.data(), 16))
      return false;
    if ((message.kind == Kind::CHALLENGE) == nonzero(message.reply_challenge.data(), 16))
      return false;
  }
  Key32 expected{};
  const bool ok = crypto_.hmac_sha256(crypto_.context, discovery_key_.data(), discovery_key_.size(), wire, kSignedSize,
                                      expected.data()) &&
                  equal(expected.data(), wire + kSignedSize, 16);
  erase(expected.data(), expected.size());
  return ok;
}

AuthDiscovery::Peer *AuthDiscovery::peer_(const Mac &mac, uint32_t now, bool create) {
  Peer *available = nullptr;
  for (auto &peer : peers_) {
    if (peer.used && peer.identity.mac == mac)
      return &peer;
    if (!peer.used || (!peer.verified && now - peer.touched_at >= kChallengeTimeoutMs))
      available = &peer;
  }
  if (!create || available == nullptr)
    return nullptr;
  *available = {};
  available->used = true;
  available->identity.mac = mac;
  available->touched_at = now;
  return available;
}

bool AuthDiscovery::challenge_(Peer &peer, const PeerIdentity &identity, uint32_t now) {
  BootNonce challenge{};
  if (!random_nonce_(challenge))
    return false;
  peer.outgoing_identity = identity;
  peer.out_challenge = challenge;
  peer.out_reply = {};
  peer.out_at = now;
  peer.out_sent_at = now;
  peer.outgoing = true;
  peer.outgoing_complete = false;
  return send_(Kind::CHALLENGE, identity, challenge, {});
}

void AuthDiscovery::verify_(Peer &peer, const PeerIdentity &identity, uint32_t now) {
  if (peer.verified && !same_identity(peer.identity, identity) && callbacks_.revoked != nullptr)
    callbacks_.revoked(callbacks_.context, peer.identity.mac);
  if (peer.identity.boot_nonce != identity.boot_nonce) {
    peer.group_highest = 0;
    peer.group_seen = 0;
  }
  peer.identity = identity;
  peer.verified = true;
  peer.verified_at = now;
  if (callbacks_.authenticated != nullptr)
    callbacks_.authenticated(callbacks_.context, identity);
}

bool AuthDiscovery::receive(const Mac &actual_source, const uint8_t *data, size_t length, uint32_t now) {
  Message message{};
  if (!decode_(actual_source, data, length, message))
    return false;
  // Check the authenticated contract before allocating a peer or challenging
  // it. Incompatible firmware must never reach link/IP admission.
  if (!mesh_protocol::compatible(local_.protocol, message.source.protocol)) {
    ++this->incompatible_count_;
    return false;
  }
  Peer *peer = peer_(actual_source, now, message.kind == Kind::HELLO || message.kind == Kind::CHALLENGE);
  if (peer == nullptr)
    return false;
  peer->touched_at = now;
  if (message.kind == Kind::HELLO) {
    // A signed recorded HELLO is neither admission nor a liveness refresh.
    if (peer->outgoing && now - peer->out_at < kChallengeTimeoutMs)
      return true;
    if (peer->verified && same_identity(peer->identity, message.source) && now - peer->verified_at < kReauthenticateMs)
      return true;
    challenge_(*peer, message.source, now);
    return true;
  }
  if (message.kind == Kind::CHALLENGE) {
    // A repeated challenge retransmits the existing response, without replacing
    // its fresh second challenge or extending its acceptance window.
    if (peer->incoming && now - peer->in_at < kChallengeTimeoutMs &&
        same_identity(peer->incoming_identity, message.source) && peer->in_challenge == message.challenge) {
      send_(Kind::RESPONSE, peer->incoming_identity, peer->in_challenge, peer->in_reply);
      return true;
    }
    BootNonce reply{};
    if (!random_nonce_(reply))
      return false;
    peer->incoming_identity = message.source;
    peer->in_challenge = message.challenge;
    peer->in_reply = reply;
    peer->in_at = now;
    peer->in_sent_at = now;
    peer->incoming = true;
    send_(Kind::RESPONSE, message.source, message.challenge, reply);
    return true;
  }
  if (message.kind == Kind::RESPONSE) {
    if (!peer->outgoing || now - peer->out_at >= kChallengeTimeoutMs ||
        !same_identity(peer->outgoing_identity, message.source) || peer->out_challenge != message.challenge ||
        (peer->outgoing_complete && peer->out_reply != message.reply_challenge))
      return false;
    peer->out_reply = message.reply_challenge;
    if (!send_(Kind::ACK, message.source, message.challenge, message.reply_challenge))
      return true;
    peer->out_sent_at = now;
    if (!peer->outgoing_complete)
      verify_(*peer, message.source, now);
    peer->outgoing_complete = true;
    return true;
  }
  if (!peer->incoming || now - peer->in_at >= kChallengeTimeoutMs ||
      !same_identity(peer->incoming_identity, message.source) || peer->in_challenge != message.challenge ||
      peer->in_reply != message.reply_challenge)
    return false;
  peer->incoming = false;  // Replay of this ACK cannot refresh admission.
  verify_(*peer, message.source, now);
  return true;
}

void AuthDiscovery::tick(uint32_t now, bool allow_transmit) {
  if (!begun_)
    return;
  if (allow_transmit && (hello_due_ || now - last_hello_ >= kHelloIntervalMs) && hello_()) {
    hello_due_ = false;
    last_hello_ = now;
  }
  for (auto &peer : peers_) {
    if (!peer.used)
      continue;
    if (peer.verified && now - peer.verified_at >= kAuthenticationLifetimeMs) {
      peer.verified = false;
      if (callbacks_.revoked != nullptr)
        callbacks_.revoked(callbacks_.context, peer.identity.mac);
    }
    if (peer.outgoing && now - peer.out_at >= kChallengeTimeoutMs)
      peer.outgoing = false;
    if (peer.incoming && now - peer.in_at >= kChallengeTimeoutMs)
      peer.incoming = false;
    if (!allow_transmit)
      continue;
    if (peer.outgoing && now - peer.out_sent_at >= kHandshakeRetryMs) {
      const Kind kind = peer.outgoing_complete ? Kind::ACK : Kind::CHALLENGE;
      if (send_(kind, peer.outgoing_identity, peer.out_challenge, peer.out_reply))
        peer.out_sent_at = now;
    }
    if (peer.incoming && now - peer.in_sent_at >= kHandshakeRetryMs &&
        send_(Kind::RESPONSE, peer.incoming_identity, peer.in_challenge, peer.in_reply))
      peer.in_sent_at = now;
    if (peer.verified && !peer.outgoing && now - peer.verified_at >= kReauthenticateMs)
      challenge_(peer, peer.identity, now);
  }
}

bool AuthDiscovery::authenticated(const Mac &mac, uint32_t now) const {
  for (const auto &peer : peers_)
    if (peer.used && peer.verified && peer.identity.mac == mac)
      return now - peer.verified_at < kAuthenticationLifetimeMs;
  return false;
}

size_t AuthDiscovery::authenticated_count(uint32_t now) const {
  size_t count = 0;
  for (const auto &peer : peers_)
    if (peer.used && peer.verified && now - peer.verified_at < kAuthenticationLifetimeMs)
      ++count;
  return count;
}

}  // namespace mesh_auto
