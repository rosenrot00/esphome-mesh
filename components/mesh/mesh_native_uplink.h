#pragma once

#include <cstdint>

namespace mesh_ip {

enum class NativeUplink : uint8_t { NATIVE_UPLINK_WIFI, NATIVE_UPLINK_ETHERNET };

inline const char *native_uplink_key(NativeUplink uplink) {
  return uplink == NativeUplink::NATIVE_UPLINK_ETHERNET ? "ETH_DEF" : "WIFI_STA_DEF";
}

}  // namespace mesh_ip
