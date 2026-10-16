#pragma once

#include "mesh_limits.h"

#include <cstdint>

namespace mesh_ip {

// Withdraw proxy forwarding before native DHCP conflict detection resumes.
// Candidate mode waits for every configured LAN edge. The bounded fallback
// exceeds the challenge-anchored 5-second forwarding grant; it does not bound
// a blocked mDNS responder's asynchronous removal or its remote cache TTLs.
class OwnershipHandover {
 public:
  void begin(uint32_t now, uint32_t nonce, uint16_t expected_mask = 0) {
    this->quiet_ = this->waiting_ = true;
    this->acked_ = false;
    this->expected_mask_ = expected_mask;
    this->acknowledged_mask_ = 0;
    this->started_ = now;
    this->nonce_ = nonce;
  }
  void acknowledge(uint32_t nonce, uint32_t now) {
    // Keep the single-gateway API compatible, but never let it bypass the
    // per-candidate proof requirement of a multi-gateway handover.
    if (this->expected_mask_ == 0 && this->waiting_ && !this->acked_ && nonce == this->nonce_) {
      this->acked_ = true;
      this->acked_at_ = now;
    }
  }
  void acknowledge(uint8_t source, uint32_t nonce, uint32_t now) {
    if (!this->waiting_ || this->acked_ || nonce != this->nonce_ || source == 0 || source > mesh_limits::MAX_NODES)
      return;
    const uint16_t bit = uint16_t(1U << (source - 1));
    if ((this->expected_mask_ & bit) == 0)
      return;
    this->acknowledged_mask_ |= bit;
    if (this->acknowledged_mask_ == this->expected_mask_) {
      this->acked_ = true;
      this->acked_at_ = now;
    }
  }
  bool ready(uint32_t now) const {
    const uint32_t elapsed = now - this->started_;
    return this->waiting_ && ((this->acked_ && uint32_t(now - this->acked_at_) >= 350) || elapsed >= 6000);
  }
  void rejoining() { this->waiting_ = false; }
  // Keep withdrawal active throughout DHCP/DAD, until STA has its address.
  void connected() {
    if (!this->waiting_)
      this->quiet_ = false;
  }
  void cancel() {
    this->quiet_ = this->waiting_ = this->acked_ = false;
    this->expected_mask_ = this->acknowledged_mask_ = 0;
  }
  bool quiet() const { return this->quiet_; }
  bool waiting() const { return this->waiting_; }
  bool acknowledged() const { return this->acked_; }
  uint32_t nonce() const { return this->nonce_; }
  uint16_t expected_mask() const { return this->expected_mask_; }
  uint16_t acknowledged_mask() const { return this->acknowledged_mask_; }

 private:
  bool quiet_{false}, waiting_{false}, acked_{false};
  uint16_t expected_mask_{0}, acknowledged_mask_{0};
  uint32_t started_{0}, acked_at_{0}, nonce_{0};
};

}  // namespace mesh_ip
