#pragma once

#include "mesh_limits.h"
#include "mesh_native_recovery.h"

#include <cstdint>
#include <array>

namespace esphome::mesh {

// The ESP32 native-Wi-Fi/IP boundary. No SDK types escape this interface.
// Mesh routing and transport backends must not depend on this class. The
// ESPHome integration owns when to take/release the shared Wi-Fi radio.
class Esp32WifiPlatform {
 public:
  enum class PowerSave : uint8_t { NONE = 0, LIGHT = 1, HIGH = 2, UNKNOWN = 255 };
  struct NativeIp {
    uint32_t address{0};
    uint32_t netmask{0};
    uint32_t gateway{0};
  };
  struct ChannelBounds {
    uint8_t first{0};
    uint8_t count{0};
  };
  struct NativeState {
    bool connected{false};
    bool roaming{false};
    bool disabled{true};
  };

  // Only the ESPHome main task reads its non-atomic Wi-Fi state. Other tasks
  // consume one coherent publication, never the component's plain fields.
  static void refresh_native_state();
  static NativeState native_state();

  static bool associated();
  // Main-task query of the current user enable/disable request. A temporary
  // coordinator pause does not change this request.
  static bool native_requested();
  static bool connected();
  // Public ESPHome status covering off-channel scan, reassociation and roam
  // recovery. A connected station can still be roaming and own the PHY.
  static bool roaming();
  static bool disabled();
  static void pause_native();
  static bool resume_native();
  // Main-task only. Stock Wi-Fi revalidates this candidate and retains all
  // credentials. The caller first completes its address-ownership barrier.
  static bool resume_native(const ::mesh_radio::NativeWifiNetwork &network,
                            const ::mesh_radio::NativeWifiCandidate &candidate);
  // Stock ESPHome ref-counted API; calls may originate from the mesh worker.
  static bool request_roaming_suppression();
  static void release_roaming_suppression();
  static bool current_channel(uint8_t &channel);
  static NativeIp native_ip();
  static bool station_address(std::array<uint8_t, 6> &address);
  // The effective policy includes ESPHome's existing force-off constraints.
  // A modem-sleep driver setting is not a measurement of RF sleep or current.
  static PowerSave configured_power_save();
  static PowerSave effective_power_save();
  static bool actual_power_save(PowerSave &mode);
  static const char *power_save_name(PowerSave mode);
  static bool start_unassociated(uint8_t channel, ChannelBounds &bounds);
  static bool switch_channel(uint8_t channel);
  static bool stop_radio();
  // Blocking scan: the integration must release its worker mutex before
  // calling and restore the mesh home channel before releasing its TX
  // reservation. One channel only; every SDK result list is cleared.
  static bool probe_native_ap(const ::mesh_radio::NativeWifiNetwork *networks, size_t count, uint8_t channel,
                              bool &found, ::mesh_radio::NativeWifiCandidate *candidate = nullptr);
};

}  // namespace esphome::mesh
