#pragma once

#include "mesh_limits.h"
#include "mesh_auto_security.h"

namespace esphome::mesh {
// ESP-IDF RNG and mbedTLS implement all cryptographic primitives. The portable
// state machine never supplies a substitute PRNG or homegrown hash function.
::mesh_auto::Crypto esp32_auto_security_crypto();
}  // namespace esphome::mesh
