#pragma once

#include "esphome/core/defines.h"
#if defined(USE_NETWORK) && defined(USE_NETWORK_PROVIDERS)
#include <array>
#include <cstddef>
#include <cstdint>
#include "ip_address.h"

namespace esphome::network {

// Proposed generic extension boundary for additional ESPHome network interfaces.
// Providers are independent of mesh and of any specific network SDK. Providers own their platform
// routing/netif work; this contract only reports lifecycle and usable addresses.
struct ConnectionProviderState {
  // Enabled means the interface is allowed to establish a connection. It may be
  // enabled while disconnected, just like an enabled Wi-Fi interface.
  bool enabled{false};
  bool connected{false};
  IPAddresses addresses{};
};

class ConnectionProvider {
 public:
  virtual ~ConnectionProvider() = default;
  virtual ConnectionProviderState network_state() const = 0;
};

// Bounded, allocation-free registration. Mutations and network utility queries
// belong to ESPHome's application context; registration is not an ISR API.
// Providers must unregister before destruction. A snapshot callback must not
// mutate this registry. Priority 0 wins; equal priorities retain registration
// order. Providers are fallback paths after native interfaces; priorities order only
// registered providers. The network utility layer owns native precedence.
class ConnectionProviderRegistry {
 public:
  static constexpr size_t CAPACITY = 4;
  bool register_provider(ConnectionProvider *provider, uint8_t priority);
  bool unregister_provider(ConnectionProvider *provider);
  bool has_providers() const { return this->size_ != 0; }
  bool has_enabled_provider() const;
  bool connected_addresses(IPAddresses &addresses) const;

 private:
  struct Entry {
    ConnectionProvider *provider{nullptr};
    uint8_t priority{0};
  };
  std::array<Entry, CAPACITY> entries_{};
  size_t size_{0};
};

ConnectionProviderRegistry &connection_provider_registry();

}  // namespace esphome::network
#endif
