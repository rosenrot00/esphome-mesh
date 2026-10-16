#pragma once

#include "mesh_limits.h"

#include <cstdint>

namespace mesh_radio {

enum class LinkRate : uint8_t { UNKNOWN, BASE, FAST };

// Directional link probing, independent of the driver and the mesh protocol.
// Only completed unicast MAC results are samples. Admission errors, idle time
// and RSSI do not demonstrate that a faster modulation can deliver traffic.
class LinkProbe {
 public:
  static constexpr uint8_t CLEAN_SUCCESSES = 32;
  static constexpr uint32_t CLEAN_FAST_MS = 60000;
  static constexpr uint16_t CONFIG_RETRY_MS = 500;

  void reset() { *this = LinkProbe{}; }
  LinkRate configured() const { return configured_; }
  bool configuration_due(uint32_t now) const {
    return !configuration_waiting_ || elapsed_(now, configuration_at_, CONFIG_RETRY_MS);
  }
  LinkRate requested(uint32_t now) const {
    if (configured_ == LinkRate::UNKNOWN || restore_base_)
      return LinkRate::BASE;
    if (configured_ == LinkRate::BASE && clean_ >= CLEAN_SUCCESSES &&
        (!holdoff_ || elapsed_(now, holdoff_at_, holdoff_ms_())))
      return LinkRate::FAST;
    return configured_;
  }
  void applied(LinkRate rate, uint32_t now) {
    configured_ = rate;
    restore_base_ = configuration_waiting_ = false;
    clean_ = 0;
    if (rate == LinkRate::FAST)
      fast_since_ = now;
  }
  void configuration_failed(LinkRate requested, uint32_t now) {
    if (requested == LinkRate::FAST)
      failed_probe_(now);
    configured_ = LinkRate::UNKNOWN;
    restore_base_ = configuration_waiting_ = true;
    configuration_at_ = now;
    clean_ = 0;
  }
  // Returns true only when this failure requires a fast-to-base transition.
  bool failed(uint32_t now) {
    clean_ = 0;
    if (configured_ != LinkRate::FAST)
      return false;
    failed_probe_(now);
    restore_base_ = true;
    return true;
  }
  void succeeded(uint32_t now) {
    if (configured_ == LinkRate::UNKNOWN || restore_base_)
      return;
    if (clean_ < CLEAN_SUCCESSES)
      clean_++;
    // A single successful probe never erases repeated failed-probe history.
    if (configured_ == LinkRate::FAST && clean_ >= CLEAN_SUCCESSES && elapsed_(now, fast_since_, CLEAN_FAST_MS))
      failed_probes_ = 0;
  }

 private:
  static bool elapsed_(uint32_t now, uint32_t then, uint32_t delay) {
    const uint32_t age = now - then;
    return age < 0x80000000U && age >= delay;
  }
  uint32_t holdoff_ms_() const {
    if (failed_probes_ == 0)
      return 0;
    return failed_probes_ >= 5 ? 60000U : 5000U << (failed_probes_ - 1);
  }
  void failed_probe_(uint32_t now) {
    if (failed_probes_ < 5)
      failed_probes_++;
    holdoff_at_ = now;
    holdoff_ = true;
  }
  LinkRate configured_{LinkRate::UNKNOWN};
  uint8_t clean_{0}, failed_probes_{0};
  bool restore_base_{false}, holdoff_{false}, configuration_waiting_{false};
  uint32_t fast_since_{0}, holdoff_at_{0}, configuration_at_{0};
};

}  // namespace mesh_radio
