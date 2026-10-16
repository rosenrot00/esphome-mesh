#pragma once

#include "esphome/core/defines.h"

#ifdef USE_ESP32

#include <esp_idf_version.h>
#include <esp_now.h>

namespace esphome::espnow_driver {

using ReceiveCallback = void (*)(const esp_now_recv_info_t *, const uint8_t *, int);
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
using SendCallback = void (*)(const esp_now_send_info_t *, esp_now_send_status_t);
#else
using SendCallback = void (*)(const uint8_t *, esp_now_send_status_t);
#endif

// The record and callback targets must remain valid until release succeeds.
// SDK callbacks must not call acquire/release or other blocking SDK functions.
struct Consumer {
  ReceiveCallback receive;
  SendCallback send;
};

// One exclusive lease covers callbacks, peers, PMK and radio-wide settings.
// Consumers may use peer/send APIs only after acquire succeeds and before release. Concurrent
// mesh and stock espnow configurations remain unsupported.
esp_err_t acquire(const Consumer &consumer);
esp_err_t release(const Consumer &consumer);
bool owns(const Consumer &consumer);

}  // namespace esphome::espnow_driver

#endif  // USE_ESP32
