#include "esphome/core/defines.h"
#ifdef USE_MESH_AUTO
#include "mesh_auto_security_crypto.h"

#include <esp_random.h>
#include <mbedtls/md.h>
#include <atomic>
#include <cstring>

namespace esphome::mesh {
namespace {
// Created during identity setup, before the worker starts. Keep the SDK hash
// context and HMAC pads for the component's lifetime instead of allocating
// them for every discovery signature or verification.
struct HmacContext {
  HmacContext() {
    mbedtls_md_init(&this->md);
    const auto *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    this->ready = info != nullptr && mbedtls_md_setup(&this->md, info, 1) == 0;
  }
  ~HmacContext() { mbedtls_md_free(&this->md); }
  mbedtls_md_context_t md{};
  std::atomic_flag busy = ATOMIC_FLAG_INIT;
  bool ready{false};
};

bool random_bytes(void *, uint8_t *output, size_t length) {
  if (output == nullptr || length == 0)
    return false;
  // The integration starts this only while the Wi-Fi radio is enabled, which
  // provides the ESP32-S3 hardware RNG's entropy source.
  esp_fill_random(output, length);
  return true;
}
bool hmac_sha256(void *context, const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                 uint8_t output[32]) {
  if (output == nullptr)
    return false;
  auto *state = static_cast<HmacContext *>(context);
  if (state == nullptr || !state->ready || key == nullptr || key_length == 0 || (data == nullptr && data_length != 0) ||
      state->busy.test_and_set(std::memory_order_acquire)) {
    std::memset(output, 0, 32);
    return false;
  }
  const bool success = mbedtls_md_hmac_starts(&state->md, key, key_length) == 0 &&
                       mbedtls_md_hmac_update(&state->md, data, data_length) == 0 &&
                       mbedtls_md_hmac_finish(&state->md, output) == 0;
  state->busy.clear(std::memory_order_release);
  if (!success)
    std::memset(output, 0, 32);
  return success;
}
}  // namespace

::mesh_auto::Crypto esp32_auto_security_crypto() {
  static HmacContext state;
  return {&state, random_bytes, hmac_sha256};
}
}  // namespace esphome::mesh
#endif  // USE_MESH_AUTO
