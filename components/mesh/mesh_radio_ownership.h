#pragma once

#include "mesh_limits.h"

#include <cstdint>

namespace mesh_radio {

struct RadioTxState {
  bool mesh_owned{false};
  bool associated{false};
  bool native_connected{false};
  bool native_roaming{false};
  bool scan_reserved{false};
  bool channel_hop_pending{false};
};

// Native association/scanning and connectionless mesh share one PHY. Native
// acquisition owns it exclusively until connected or explicitly handed over.
// This budget bounds our ownership phase, not ESPHome's internal retry cycle.
class RadioOwnership {
 public:
  static constexpr uint32_t NATIVE_ACQUISITION_MS = 60000;
  // An AP hint avoids scanning, but authentication and DHCP still need the
  // normal acquisition window. A shorter deadline can repeatedly abort retries.
  static constexpr uint32_t NATIVE_RECOVERY_MS = NATIVE_ACQUISITION_MS;
  static constexpr uint32_t PARENT_CHANNEL_MAX_AGE_MS = 2000;

  static bool lifecycle_allowed(const RadioTxState &state) {
    // A connected background scan keeps the existing SDK/peer state alive.
    // Initial acquisition and disconnected reassociation still own the PHY.
    return state.mesh_owned || (state.associated && state.native_connected);
  }

  static bool transmit_allowed(const RadioTxState &state) {
    return !state.scan_reserved && !state.channel_hop_pending && (state.mesh_owned || !state.native_roaming) &&
           lifecycle_allowed(state);
  }

  void start_native_acquisition(uint32_t now, bool returning_from_mesh = false) {
    acquisition_started_ = now;
    acquisition_budget_ = returning_from_mesh ? NATIVE_RECOVERY_MS : NATIVE_ACQUISITION_MS;
    native_connected_ = false;
    fast_handover_ = false;
  }

  void observe_native(uint32_t now, bool connected) {
    if (connected) {
      native_connected_ = true;
      return;
    }
    if (native_connected_) {
      acquisition_started_ = now;
      acquisition_budget_ = NATIVE_ACQUISITION_MS;
      native_connected_ = false;
      fast_handover_ = true;
    }
  }

  bool fallback_due(uint32_t now, bool remote_route, bool roaming) const {
    if (native_connected_)
      return false;
    const uint32_t age = now - acquisition_started_;
    // Short managed roams retain native priority. RECONNECTING can remain set
    // indefinitely when an AP disappears, so only the fast path is deferred;
    // the bounded acquisition deadline must still release the radio.
    return (fast_handover_ && remote_route && !roaming) || (age < 0x80000000U && age >= acquisition_budget_);
  }

  // Only call after full wire/auth/policy checks and Core has selected this
  // immediate sender as parent. A driver's transient scan channel is no hint.
  void observe_parent_channel(uint32_t now, uint8_t sender, uint8_t parent, uint8_t channel) {
    if (sender == 0 || sender != parent || channel < 1 || channel > 14)
      return;
    parent_channel_ = channel;
    parent_channel_seen_ = now;
  }

  uint8_t preferred_mesh_channel(uint32_t now, uint8_t fallback) const {
    const uint32_t age = now - parent_channel_seen_;
    if (parent_channel_ != 0 && age < PARENT_CHANNEL_MAX_AGE_MS)
      return parent_channel_;
    return fallback >= 1 && fallback <= 14 ? fallback : 1;
  }

 protected:
  uint32_t acquisition_started_{0}, parent_channel_seen_{0}, acquisition_budget_{NATIVE_ACQUISITION_MS};
  uint8_t parent_channel_{0};
  bool native_connected_{false}, fast_handover_{false};
};

}  // namespace mesh_radio
