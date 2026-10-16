#pragma once

#include "mesh_limits.h"

#include <cstdint>

namespace mesh_radio {

struct RadioSearchState {
  bool mesh_owned{false};
  bool wifi_disabled{false};
  bool associated{false};
  bool quiet{false};
  bool scanning{false};
  bool route_connected{false};
  uint8_t route_root{0};
  uint8_t gateway{0};
};

// Acquisition changes the channel only after the authenticated mesh route has
// expired. A usable route pins the radio; associated Wi-Fi always owns its PHY.
class ChannelSearch {
 public:
  static constexpr uint32_t DWELL_MS = 1000;
  static constexpr uint32_t RETRY_MS = 250;

  static bool eligible(const RadioSearchState &state) {
    const bool usable_route = state.route_connected && (state.gateway == 0 || state.route_root == state.gateway);
    return state.gateway != 0 && state.mesh_owned && state.wifi_disabled && !state.associated && !state.quiet &&
           !state.scanning && !usable_route;
  }

  void set_country(uint8_t first, uint8_t count) {
    if (first < 1 || first > 14 || count == 0 || unsigned(first) + count > 15) {
      first_ = 1;
      last_ = 11;
    } else {
      first_ = first;
      last_ = first + count - 1;
    }
  }

  uint8_t candidate(uint32_t now, uint8_t current, const RadioSearchState &state) {
    if (!eligible(state)) {
      searching_ = false;
      pending_ = 0;
      return 0;
    }
    if (!searching_ || current != current_) {
      searching_ = true;
      current_ = current;
      since_ = now;
      pending_ = 0;
      retrying_ = false;
      return 0;
    }
    if (pending_ != 0)
      return !retrying_ || now - last_attempt_ >= RETRY_MS ? pending_ : 0;
    if (now - since_ < DWELL_MS)
      return 0;
    const uint8_t next = current < first_ || current >= last_ ? first_ : current + 1;
    // A country permitting one channel has nothing to search.
    if (next == current) {
      since_ = now;
      return 0;
    }
    pending_ = next;
    return pending_;
  }

  void complete(uint32_t now, uint8_t channel, bool success) {
    if (pending_ == 0 || channel != pending_)
      return;
    if (success) {
      current_ = channel;
      since_ = now;
      pending_ = 0;
      retrying_ = false;
    } else {
      last_attempt_ = now;
      retrying_ = true;
    }
  }

  bool searching() const { return searching_; }

 protected:
  uint8_t first_{1}, last_{11}, current_{0}, pending_{0};
  uint32_t since_{0}, last_attempt_{0};
  bool searching_{false}, retrying_{false};
};

}  // namespace mesh_radio
