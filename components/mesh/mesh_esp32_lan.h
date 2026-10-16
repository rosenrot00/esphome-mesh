#pragma once

#include "mesh_esp32_platform.h"
#include "mesh_native_uplink.h"

namespace esphome::mesh {

// LAN selection is independent of ownership of the ESP-NOW/Wi-Fi PHY.
class Esp32LanPlatform {
 public:
  static void refresh_native_state();  // ESPHome main task only.
  static bool ethernet_connected();
  static ::mesh_ip::NativeUplink select_uplink(bool wifi_connected);
  static Esp32WifiPlatform::NativeIp native_ip(::mesh_ip::NativeUplink uplink);
};

}  // namespace esphome::mesh
