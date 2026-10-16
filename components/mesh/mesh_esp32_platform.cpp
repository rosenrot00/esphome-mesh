#include "mesh_esp32_platform.h"

#include "esphome/core/defines.h"
#ifdef USE_WIFI
#include "esphome/components/wifi/wifi_component.h"
#endif
#include "esphome/core/log.h"

#include <esp_netif.h>
#include <esp_wifi.h>
#include <soc/soc_caps.h>
#include <atomic>
#include <limits>

#ifndef MESH_WIFI_POWER_SAVE_MODE
#define MESH_WIFI_POWER_SAVE_MODE 0
#endif
#ifndef MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE
#define MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE MESH_WIFI_POWER_SAVE_MODE
#endif

namespace esphome::mesh {
namespace {
const char *const TAG = "mesh.platform";
std::atomic<uint8_t> native_state_bits{4};
static_assert(MESH_WIFI_POWER_SAVE_MODE >= 0 && MESH_WIFI_POWER_SAVE_MODE <= 2,
              "Configured Wi-Fi power save mode must be NONE, LIGHT or HIGH");
static_assert(MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE >= 0 && MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE <= 2,
              "Effective Wi-Fi power save mode must be NONE, LIGHT or HIGH");

}  // namespace

void Esp32WifiPlatform::refresh_native_state() {
  uint8_t bits = 4;
#ifdef USE_WIFI
  if (wifi::global_wifi_component != nullptr) {
    const auto *component = wifi::global_wifi_component;
    bits = (component->is_connected() ? 1U : 0U) | (component->is_roaming() ? 2U : 0U) |
           (wifi::global_wifi_component->is_disabled() ? 4U : 0U);
  }
#endif
  native_state_bits.store(bits);
}

Esp32WifiPlatform::NativeState Esp32WifiPlatform::native_state() {
  const uint8_t bits = native_state_bits.load();
  return {(bits & 1U) != 0, (bits & 2U) != 0, (bits & 4U) != 0};
}

bool Esp32WifiPlatform::associated() {
  wifi_ap_record_t ap{};
  return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
}

bool Esp32WifiPlatform::connected() {
  return native_state().connected;
}

bool Esp32WifiPlatform::roaming() {
  return native_state().roaming;
}

bool Esp32WifiPlatform::disabled() {
  return native_state().disabled;
}

bool Esp32WifiPlatform::native_requested() {
#ifdef USE_WIFI
  return wifi::global_wifi_component != nullptr && wifi::global_wifi_component->native_enabled_requested();
#else
  return false;
#endif
}

void Esp32WifiPlatform::pause_native() {
#ifdef USE_WIFI
  if (wifi::global_wifi_component != nullptr)
    wifi::global_wifi_component->pause_native();
#endif
  refresh_native_state();
}

bool Esp32WifiPlatform::resume_native() {
  bool accepted = false;
#ifdef USE_WIFI
  if (wifi::global_wifi_component != nullptr)
    accepted = wifi::global_wifi_component->resume_native();
#endif
  refresh_native_state();
  return accepted;
}

bool Esp32WifiPlatform::resume_native(const ::mesh_radio::NativeWifiNetwork &network,
                                      const ::mesh_radio::NativeWifiCandidate &candidate) {
#ifdef USE_WIFI
  const char *ssid = network.hidden ? "" : network.ssid;
  const size_t length = ssid == nullptr ? 0 : std::strlen(ssid);
  // A wildcard SSID needs another scan: the bounded metadata slot does not
  // retain the AP name. A hidden network instead keeps its configured name.
  if (ssid != nullptr && (network.hidden || length != 0) && length <= 32 &&
      candidate.valid(std::numeric_limits<size_t>::max()) && candidate.hidden == network.hidden &&
      network.matches(reinterpret_cast<const uint8_t *>(ssid), length, candidate.bssid.data(), candidate.channel,
                      candidate.authenticated)) {
    if (wifi::global_wifi_component != nullptr) {
      const wifi::WiFiScanResult observed(candidate.bssid, ssid, length, candidate.channel, candidate.rssi,
                                         candidate.authenticated, candidate.hidden);
      const bool accepted = wifi::global_wifi_component->resume_native(observed);
      refresh_native_state();
      return accepted;
    }
    refresh_native_state();
    return false;
  }
#else
  (void) network;
  (void) candidate;
#endif
  return resume_native();
}

bool Esp32WifiPlatform::request_roaming_suppression() {
#if defined(USE_WIFI) && defined(USE_WIFI_RUNTIME_ROAMING_SUPPRESSION)
  if (wifi::global_wifi_component != nullptr) {
    wifi::global_wifi_component->request_roaming_suppression();
    return true;
  }
#endif
  return false;
}

void Esp32WifiPlatform::release_roaming_suppression() {
#if defined(USE_WIFI) && defined(USE_WIFI_RUNTIME_ROAMING_SUPPRESSION)
  if (wifi::global_wifi_component != nullptr)
    wifi::global_wifi_component->release_roaming_suppression();
#endif
}

bool Esp32WifiPlatform::current_channel(uint8_t &channel) {
  channel = 0;
  wifi_second_chan_t secondary;
  const bool success = esp_wifi_get_channel(&channel, &secondary) == ESP_OK && channel >= 1 && channel <= 14;
  if (!success)
    channel = 0;
  return success;
}

Esp32WifiPlatform::NativeIp Esp32WifiPlatform::native_ip() {
  esp_netif_ip_info_t info{};
  auto *station = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (station != nullptr && esp_netif_get_ip_info(station, &info) == ESP_OK)
    return {info.ip.addr, info.netmask.addr, info.gw.addr};
  return {};
}

bool Esp32WifiPlatform::station_address(std::array<uint8_t, 6> &address) {
  return esp_wifi_get_mac(WIFI_IF_STA, address.data()) == ESP_OK;
}

Esp32WifiPlatform::PowerSave Esp32WifiPlatform::configured_power_save() {
  return static_cast<PowerSave>(MESH_WIFI_POWER_SAVE_MODE);
}

Esp32WifiPlatform::PowerSave Esp32WifiPlatform::effective_power_save() {
  return static_cast<PowerSave>(MESH_WIFI_POWER_SAVE_EFFECTIVE_MODE);
}

bool Esp32WifiPlatform::actual_power_save(PowerSave &mode) {
  mode = PowerSave::UNKNOWN;
  wifi_ps_type_t actual;
  if (esp_wifi_get_ps(&actual) != ESP_OK)
    return false;
  switch (actual) {
    case WIFI_PS_NONE:
      mode = PowerSave::NONE;
      return true;
    case WIFI_PS_MIN_MODEM:
      mode = PowerSave::LIGHT;
      return true;
    case WIFI_PS_MAX_MODEM:
      mode = PowerSave::HIGH;
      return true;
    default:
      return false;
  }
}

const char *Esp32WifiPlatform::power_save_name(PowerSave mode) {
  switch (mode) {
    case PowerSave::NONE:
      return "NONE";
    case PowerSave::LIGHT:
      return "LIGHT";
    case PowerSave::HIGH:
      return "HIGH";
    default:
      return "UNKNOWN";
  }
}

bool Esp32WifiPlatform::start_unassociated(uint8_t channel, ChannelBounds &bounds) {
  bounds = {};
  if (channel < 1 || channel > 14)
    return false;
  wifi_mode_t mode;
  esp_err_t err = esp_wifi_get_mode(&mode);
  if (err == ESP_ERR_WIFI_NOT_INIT) {
    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    config.nvs_enable = false;
    err = esp_wifi_init(&config);
  }
  if (err == ESP_OK)
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (err == ESP_OK)
    err = esp_wifi_set_mode(WIFI_MODE_STA);
  if (err == ESP_OK)
    err = esp_wifi_start();
#ifdef SOC_WIFI_SUPPORT_5G
  // The current mesh adapter and mixed-chip peers share 2.4 GHz channels.
  // Native Wi-Fi uses the same band policy via schema final validation.
  if (err == ESP_OK)
    err = esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY);
#endif
  if (err == ESP_OK)
    err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (err == ESP_OK) {
    wifi_ps_type_t power_save = WIFI_PS_NONE;
    switch (effective_power_save()) {
      case PowerSave::LIGHT:
        power_save = WIFI_PS_MIN_MODEM;
        break;
      case PowerSave::HIGH:
        power_save = WIFI_PS_MAX_MODEM;
        break;
      default:
        break;
    }
    err = esp_wifi_set_ps(power_save);
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Unassociated radio failed: %s", esp_err_to_name(err));
    return false;
  }
  wifi_country_t country{};
  if (esp_wifi_get_country(&country) == ESP_OK)
    bounds = {country.schan, country.nchan};
  return true;
}

bool Esp32WifiPlatform::switch_channel(uint8_t channel) {
  if (channel < 1 || channel > 14)
    return false;
  const esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK)
    ESP_LOGW(TAG, "Channel %u rejected: %s", channel, esp_err_to_name(err));
  return err == ESP_OK;
}

bool Esp32WifiPlatform::stop_radio() {
  const esp_err_t err = esp_wifi_stop();
  if (err != ESP_OK && err != ESP_ERR_WIFI_NOT_STARTED)
    ESP_LOGW(TAG, "Stopping shared Wi-Fi radio: %s", esp_err_to_name(err));
  return err == ESP_OK || err == ESP_ERR_WIFI_NOT_STARTED;
}

bool Esp32WifiPlatform::probe_native_ap(const ::mesh_radio::NativeWifiNetwork *networks, size_t network_count,
                                        uint8_t channel, bool &found, ::mesh_radio::NativeWifiCandidate *candidate) {
  found = false;
  if (candidate != nullptr)
    *candidate = {};
  if (networks == nullptr || network_count == 0 || channel < 1 || channel > 14)
    return false;
  wifi_scan_config_t scan{};
  scan.show_hidden = true;
  scan.channel = channel;
  scan.scan_type = WIFI_SCAN_TYPE_ACTIVE;
  scan.scan_time.active.min = 30;
  scan.scan_time.active.max = 60;
  const esp_err_t err = esp_wifi_scan_start(&scan, true);
  if (err != ESP_OK) {
    esp_wifi_clear_ap_list();
    return false;
  }
  uint16_t count = 0;
  bool success = esp_wifi_scan_get_ap_num(&count) == ESP_OK;
  for (uint16_t index = 0; success && index < count && !found; ++index) {
    wifi_ap_record_t record{};
    success = esp_wifi_scan_get_ap_record(&record) == ESP_OK;
    if (!success)
      break;
    size_t length = 0;
    while (length < sizeof(record.ssid) && record.ssid[length] != 0)
      ++length;
    ::mesh_radio::NativeWifiCandidate observed;
    std::memcpy(observed.bssid.data(), record.bssid, observed.bssid.size());
    observed.channel = record.primary;
    observed.rssi = record.rssi;
    observed.authenticated = record.authmode != WIFI_AUTH_OPEN;
    observed.hidden = length == 0;
    if (length > 32 || record.primary != channel || !observed.valid(network_count))
      continue;
    for (size_t network = 0; network < network_count && !found; ++network) {
      found = networks[network].matches(record.ssid, length, record.bssid, record.primary, observed.authenticated);
      if (found && candidate != nullptr) {
        observed.network_index = network;
        *candidate = observed;
      }
    }
  }
  // get_ap_record consumes one result at a time. Clear the rest on a match,
  // malformed/error response, empty result and normal completion alike.
  success = (esp_wifi_clear_ap_list() == ESP_OK) && success;
  if (!success) {
    found = false;
    if (candidate != nullptr)
      *candidate = {};
  }
  return success;
}

}  // namespace esphome::mesh
