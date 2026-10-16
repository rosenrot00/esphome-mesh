#include "connection_provider.h"
#if defined(USE_NETWORK) && defined(USE_NETWORK_PROVIDERS)

namespace esphome::network {

bool ConnectionProviderRegistry::register_provider(ConnectionProvider *provider, uint8_t priority) {
  if (provider == nullptr || this->size_ == CAPACITY)
    return false;
  for (size_t i = 0; i < this->size_; ++i) {
    if (this->entries_[i].provider == provider)
      return false;
  }
  size_t position = this->size_;
  while (position != 0 && this->entries_[position - 1].priority > priority) {
    this->entries_[position] = this->entries_[position - 1];
    --position;
  }
  this->entries_[position] = {provider, priority};
  ++this->size_;
  return true;
}

bool ConnectionProviderRegistry::unregister_provider(ConnectionProvider *provider) {
  for (size_t i = 0; i < this->size_; ++i) {
    if (this->entries_[i].provider != provider)
      continue;
    for (size_t j = i + 1; j < this->size_; ++j)
      this->entries_[j - 1] = this->entries_[j];
    this->entries_[--this->size_] = {};
    return true;
  }
  return false;
}

bool ConnectionProviderRegistry::has_enabled_provider() const {
  for (size_t i = 0; i < this->size_; ++i) {
    if (this->entries_[i].provider->network_state().enabled)
      return true;
  }
  return false;
}

bool ConnectionProviderRegistry::connected_addresses(IPAddresses &addresses) const {
  for (size_t i = 0; i < this->size_; ++i) {
    const auto state = this->entries_[i].provider->network_state();
    if (!state.enabled || !state.connected)
      continue;
    for (const auto &address : state.addresses) {
      if (!address.is_set())
        continue;
      addresses = state.addresses;
      return true;
    }
  }
  addresses = {};
  return false;
}

ConnectionProviderRegistry &connection_provider_registry() {
  static ConnectionProviderRegistry registry;
  return registry;
}

}  // namespace esphome::network
#endif
