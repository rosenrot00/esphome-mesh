#include "espnow_driver.h"

#ifdef USE_ESP32

#include <freertos/FreeRTOS.h>

namespace esphome::espnow_driver {
namespace {
struct DriverState {
  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  const Consumer *owner{nullptr};
  uint32_t readers{0};
  bool operation{false};
  bool initialized{false};
  bool accepting{false};
  bool stopping{false};
};

DriverState state;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

const Consumer *begin_callback() {
  portENTER_CRITICAL(&state.lock);
  const Consumer *consumer = state.accepting ? state.owner : nullptr;
  if (consumer != nullptr)
    state.readers++;
  portEXIT_CRITICAL(&state.lock);
  return consumer;
}

void end_callback() {
  portENTER_CRITICAL(&state.lock);
  state.readers--;
  portEXIT_CRITICAL(&state.lock);
}

void receive_callback(const esp_now_recv_info_t *info, const uint8_t *data, int length) {
  const Consumer *consumer = begin_callback();
  if (consumer == nullptr)
    return;
  if (info != nullptr && data != nullptr)
    consumer->receive(info, data, length);
  end_callback();
}

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void send_callback(const esp_now_send_info_t *info, esp_now_send_status_t status) {
#else
void send_callback(const uint8_t *info, esp_now_send_status_t status) {
#endif
  const Consumer *consumer = begin_callback();
  if (consumer == nullptr)
    return;
  if (info != nullptr)
    consumer->send(info, status);
  end_callback();
}
}  // namespace

bool owns(const Consumer &consumer) {
  portENTER_CRITICAL(&state.lock);
  const bool result = state.owner == &consumer;
  portEXIT_CRITICAL(&state.lock);
  return result;
}

esp_err_t acquire(const Consumer &consumer) {
  if (consumer.receive == nullptr || consumer.send == nullptr)
    return ESP_ERR_ESPNOW_ARG;
  portENTER_CRITICAL(&state.lock);
  if (state.operation || (state.owner != nullptr && state.owner != &consumer) || state.stopping) {
    portEXIT_CRITICAL(&state.lock);
    return ESP_ERR_ESPNOW_INTERNAL;
  }
  if (state.owner == &consumer && state.accepting) {
    portEXIT_CRITICAL(&state.lock);
    return ESP_OK;
  }
  state.operation = true;
  state.owner = &consumer;
  portEXIT_CRITICAL(&state.lock);

  esp_err_t error = esp_now_init();
  const bool initialized = error == ESP_OK;
  if (error == ESP_OK)
    error = esp_now_register_recv_cb(receive_callback);
  if (error == ESP_OK)
    error = esp_now_register_send_cb(send_callback);
  bool retained = initialized;
  if (error != ESP_OK && initialized) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    retained = esp_now_deinit() != ESP_OK;
  }

  portENTER_CRITICAL(&state.lock);
  state.initialized = retained;
  state.accepting = error == ESP_OK;
  state.stopping = error != ESP_OK && retained;
  state.operation = false;
  if (!retained)
    state.owner = nullptr;
  portEXIT_CRITICAL(&state.lock);
  return error;
}

esp_err_t release(const Consumer &consumer) {
  portENTER_CRITICAL(&state.lock);
  if (state.owner == nullptr) {
    portEXIT_CRITICAL(&state.lock);
    return ESP_OK;
  }
  if (state.owner != &consumer || state.operation) {
    portEXIT_CRITICAL(&state.lock);
    return ESP_ERR_ESPNOW_INTERNAL;
  }
  state.operation = true;
  state.accepting = false;
  state.stopping = true;
  const bool initialized = state.initialized;
  portEXIT_CRITICAL(&state.lock);

  esp_err_t error = ESP_OK;
  if (initialized) {
    esp_now_unregister_recv_cb();
    esp_now_unregister_send_cb();
    error = esp_now_deinit();
  }
  portENTER_CRITICAL(&state.lock);
  if (error == ESP_OK) {
    state.initialized = false;
    // A callback may have captured the consumer before unregister/deinit.
    // Keep its record leased until every such invocation has returned.
    if (state.readers == 0) {
      state.owner = nullptr;
      state.stopping = false;
    } else {
      error = ESP_ERR_ESPNOW_INTERNAL;
    }
  }
  state.operation = false;
  portEXIT_CRITICAL(&state.lock);
  return error;
}

}  // namespace esphome::espnow_driver

#endif  // USE_ESP32
