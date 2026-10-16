#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mesh_radio {

// The literals are owned by generated code; credentials stay in stock Wi-Fi.
struct NativeWifiNetwork {
  const char *ssid{nullptr};
  std::array<uint8_t, 6> bssid{};
  uint8_t channel{0};
  bool has_bssid{false};
  bool hidden{false};
  bool requires_auth{false};

  bool matches(const uint8_t *scan_ssid, size_t ssid_length, const uint8_t *scan_bssid, uint8_t scan_channel,
               bool authenticated) const {
    if (this->ssid == nullptr)
      return false;
    // Keep the same selection rules as WiFiScanResult::matches. Hidden
    // candidates are tried by stock Wi-Fi with its original credentials.
    if (this->hidden) {
      if (ssid_length != 0)
        return false;
    } else {
      const size_t configured_length = std::strlen(this->ssid);
      if (configured_length != 0 &&
          (configured_length != ssid_length || std::memcmp(this->ssid, scan_ssid, ssid_length) != 0))
        return false;
    }
    return (!this->has_bssid || std::memcmp(this->bssid.data(), scan_bssid, this->bssid.size()) == 0) &&
           (this->channel == 0 || this->channel == scan_channel) && this->requires_auth == authenticated;
  }
};

// Scan metadata only. The network literal and credentials have separate owners.
struct NativeWifiCandidate {
  size_t network_index{0};
  std::array<uint8_t, 6> bssid{};
  uint8_t channel{0};
  int8_t rssi{0};
  bool authenticated{false};
  bool hidden{false};

  bool valid(size_t network_count) const {
    return this->network_index < network_count && this->channel >= 1 && this->channel <= 14 &&
           this->bssid != std::array<uint8_t, 6>{} && (this->bssid[0] & 1) == 0;
  }
};

// Each short channel visit releases its TX reservation after restoring home.
// Unsigned elapsed arithmetic also covers millis() wraparound.
class NativeRecovery {
 public:
  static constexpr uint32_t ROUND_MS = 60000;
  static constexpr uint32_t STEP_MS = 1000;

  void set_country(uint8_t first, uint8_t count) {
    if (first < 1 || first > 14 || count == 0 || unsigned(first) + count > 15) {
      this->first_ = 1;
      this->last_ = 11;
    } else {
      this->first_ = first;
      this->last_ = first + count - 1;
    }
    this->cancel();
  }

  bool due(uint32_t now, uint32_t last_round) const {
    return this->active_ ? now - this->last_step_ >= STEP_MS : now - last_round >= ROUND_MS;
  }

  uint8_t next(uint32_t now, uint8_t home, uint32_t &last_round) {
    if (!this->due(now, last_round))
      return 0;
    if (!this->active_) {
      this->active_ = true;
      this->visited_ = 0;
      last_round = now;
      if (home >= this->first_ && home <= this->last_)
        return home;
    }
    for (uint8_t channel = this->first_; channel <= this->last_; ++channel)
      if ((this->visited_ & (1U << (channel - 1))) == 0)
        return channel;
    return 0;
  }

  void complete(uint32_t now, uint8_t channel) {
    this->visited_ |= uint16_t(1U << (channel - 1));
    this->last_step_ = now;
    uint16_t legal = 0;
    for (uint8_t value = this->first_; value <= this->last_; ++value)
      legal |= uint16_t(1U << (value - 1));
    if ((this->visited_ & legal) == legal)
      this->active_ = false;
  }

  void cancel() {
    this->active_ = false;
    this->visited_ = 0;
  }

 protected:
  uint32_t last_step_{0};
  uint16_t visited_{0};
  uint8_t first_{1}, last_{11};
  bool active_{false};
};

}  // namespace mesh_radio
