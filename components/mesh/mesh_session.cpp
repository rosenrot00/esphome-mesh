#include "mesh_session.h"

namespace mesh_session {
namespace {
bool live(uint32_t now, uint32_t started) { return uint32_t(now - started) < PROOF_LIFETIME_MS; }
}  // namespace

bool ManualBootSessionRegistry::configure(uint8_t own_node, uint64_t own_boot, uint16_t allowed_nodes) {
  if (own_node_ != 0 || !mesh_limits::valid_node(own_node) || own_boot == 0 ||
      (allowed_nodes & ~mesh_limits::ID_MASK) != 0 || (allowed_nodes & (1U << (own_node - 1))) == 0)
    return false;
  own_node_ = own_node;
  own_boot_ = own_boot;
  allowed_nodes_ = allowed_nodes;
  return true;
}
bool ManualBootSessionRegistry::offer_(Peer &peer, uint64_t boot, uint32_t now, uint64_t nonce) {
  if (boot == peer.proved || (peer.challenge != 0 && live(now, peer.started)))
    return false;
  // The first value is unpredictable; thereafter uniqueness lasts for this
  // entire requester boot, including retries after timeout and old HELLOs.
  // There is no wrap fallback that could revive a recorded proof.
  if (peer.last_nonce == UINT64_MAX)
    return false;
  if (peer.last_nonce != 0)
    nonce = peer.last_nonce + 1;
  else if (nonce == 0 || nonce == UINT64_MAX)
    return false;
  peer.candidate = boot;
  peer.challenge = peer.last_nonce = nonce;
  peer.started = now;
  peer.last_sent = 0;
  peer.challenge_sent = false;
  return true;
}
ManualBootSessionRegistry::Result ManualBootSessionRegistry::receive(uint8_t source, uint8_t destination,
                                                                     const Message &message, uint32_t now,
                                                                     uint64_t random_nonce) {
  if (own_node_ == 0 || source == own_node_ || !valid(message, source, destination) ||
      (allowed_nodes_ & (1U << (source - 1))) == 0 || (destination != 0 && destination != own_node_))
    return Result::REJECTED;
  auto &peer = peers_[source - 1];
  if (message.kind == Kind::HELLO) {
    offer_(peer, message.source_boot, now, random_nonce);
    return Result::ACCEPTED;
  }
  if (message.kind == Kind::CHALLENGE) {
    if (peer.reply_nonce == 0 || !live(now, peer.reply_started)) {
      peer.reply_boot = message.source_boot;
      peer.reply_nonce = message.nonce;
      peer.reply_started = now;
    }
    offer_(peer, message.source_boot, now, random_nonce);
    return Result::ACCEPTED;
  }
  if (message.destination_boot != own_boot_)
    return Result::REJECTED;
  if (peer.challenge == 0 || !peer.challenge_sent || !live(now, peer.started) || peer.challenge != message.nonce)
    return Result::REJECTED;
  peer.challenge = 0;
  peer.challenge_sent = false;
  peer.candidate = message.source_boot;
  if (peer.proved == message.source_boot)
    return Result::ACCEPTED;
  peer.proved = message.source_boot;
  peer.ready = false;
  return Result::CHANGED;
}
bool ManualBootSessionRegistry::next_outgoing(uint32_t now, Outgoing &outgoing) {
  if (own_node_ == 0)
    return false;
  bool all_ready = true;
  for (size_t i = 0; i < mesh_limits::MAX_NODES; ++i) {
    const uint8_t index = static_cast<uint8_t>((cursor_ + i) % mesh_limits::MAX_NODES);
    auto &peer = peers_[index];
    if (index + 1 == own_node_ || (allowed_nodes_ & (1U << index)) == 0)
      continue;
    all_ready &= peer.ready;
    if (peer.reply_nonce != 0 && !live(now, peer.reply_started))
      peer.reply_nonce = 0;
    if (peer.challenge != 0 && !live(now, peer.started)) {
      peer.challenge = 0;
      peer.challenge_sent = false;
      // Lost one-way replies must recover even if the other node has already
      // proved every peer and stopped HELLO. Query its present session again.
      offer_(peer, peer.candidate, now, 0);
    }
    Message message;
    message.source_boot = own_boot_;
    if (peer.reply_nonce != 0 && live(now, peer.reply_started)) {
      message.kind = Kind::RESPONSE;
      message.destination_boot = peer.reply_boot;
      message.nonce = peer.reply_nonce;
    } else if (peer.challenge != 0 && live(now, peer.started) &&
               (!peer.challenge_sent || uint32_t(now - peer.last_sent) >= RETRY_INTERVAL_MS)) {
      message.kind = Kind::CHALLENGE;
      message.nonce = peer.challenge;
    } else
      continue;
    outgoing.destination = index + 1;
    outgoing.message = message;
    cursor_ = (index + 1) % mesh_limits::MAX_NODES;
    return true;
  }
  if (!all_ready && (!hello_sent_ || uint32_t(now - last_hello_) >= HELLO_INTERVAL_MS)) {
    outgoing = {};
    outgoing.message.source_boot = own_boot_;
    return true;
  }
  return false;
}
bool ManualBootSessionRegistry::sent(const Outgoing &outgoing, uint32_t now) {
  if (!valid(outgoing.message, own_node_, outgoing.destination) || outgoing.message.source_boot != own_boot_)
    return false;
  if (outgoing.message.kind == Kind::HELLO) {
    last_hello_ = now;
    hello_sent_ = true;
    return true;
  }
  auto &peer = peers_[outgoing.destination - 1];
  if (outgoing.message.kind == Kind::RESPONSE) {
    if (outgoing.message.nonce != peer.reply_nonce || outgoing.message.destination_boot != peer.reply_boot ||
        !live(now, peer.reply_started))
      return false;
    peer.reply_nonce = 0;
    return true;
  }
  if (outgoing.message.nonce != peer.challenge || !live(now, peer.started))
    return false;
  peer.challenge_sent = true;
  peer.last_sent = now;
  return true;
}
uint64_t ManualBootSessionRegistry::proved_boot(uint8_t node) const {
  if (!mesh_limits::valid_node(node) || (allowed_nodes_ & (1U << (node - 1))) == 0)
    return 0;
  return node == own_node_ ? own_boot_ : peers_[node - 1].proved;
}
uint64_t ManualBootSessionRegistry::session(uint8_t node) const {
  if (!mesh_limits::valid_node(node) || (allowed_nodes_ & (1U << (node - 1))) == 0)
    return 0;
  return node == own_node_ ? own_boot_ : peers_[node - 1].ready ? peers_[node - 1].proved : 0;
}
bool ManualBootSessionRegistry::activate(uint8_t node, uint64_t proved) {
  if (!mesh_limits::valid_node(node) || node == own_node_ || proved == 0 || peers_[node - 1].proved != proved)
    return false;
  peers_[node - 1].ready = true;
  return true;
}

}  // namespace mesh_session
