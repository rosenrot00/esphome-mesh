#include "mesh_esp32_lan.h"

#include "esphome/core/defines.h"
#ifdef USE_ETHERNET
#include "esphome/components/ethernet/ethernet_component.h"
#include <atomic>
#endif
#include <esp_netif.h>

namespace esphome::mesh {

#ifdef USE_ETHERNET
namespace {
std::atomic<bool> ethernet_ready{false};
}
#endif

void Esp32LanPlatform::refresh_native_state() {
#ifdef USE_ETHERNET
  auto *component = ethernet::global_eth_component;
  ethernet_ready.store(component != nullptr && !component->is_disabled() && component->is_connected());
#endif
}

bool Esp32LanPlatform::ethernet_connected() {
#ifdef USE_ETHERNET
  return ethernet_ready.load();
#else
  return false;
#endif
}

::mesh_ip::NativeUplink Esp32LanPlatform::select_uplink(bool wifi_connected) {
#ifdef USE_ETHERNET
#ifdef USE_NETWORK_PRIMARY_INTERFACE_WIFI
  if (wifi_connected)
    return ::mesh_ip::NativeUplink::NATIVE_UPLINK_WIFI;
#endif
  if (ethernet_connected() || !wifi_connected)
    return ::mesh_ip::NativeUplink::NATIVE_UPLINK_ETHERNET;
#else
  (void) wifi_connected;
#endif
  return ::mesh_ip::NativeUplink::NATIVE_UPLINK_WIFI;
}

Esp32WifiPlatform::NativeIp Esp32LanPlatform::native_ip(::mesh_ip::NativeUplink uplink) {
  esp_netif_ip_info_t info{};
  auto *interface = esp_netif_get_handle_from_ifkey(::mesh_ip::native_uplink_key(uplink));
  if (interface != nullptr && esp_netif_get_ip_info(interface, &info) == ESP_OK)
    return {info.ip.addr, info.netmask.addr, info.gw.addr};
  return {};
}

}  // namespace esphome::mesh
