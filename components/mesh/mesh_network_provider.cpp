#include "mesh_network_provider.h"
#ifdef USE_MESH_IP
#include "mesh_component.h"
#include <cstring>

namespace esphome::mesh {

bool MeshNetworkProvider::start(MeshComponent *component) {
  if (component == nullptr || this->component_ != nullptr ||
      !network::connection_provider_registry().register_provider(this, 0))
    return false;
  this->component_ = component;
  return true;
}

void MeshNetworkProvider::stop() {
  network::connection_provider_registry().unregister_provider(this);
  this->component_ = nullptr;
}

network::ConnectionProviderState MeshNetworkProvider::network_state() const {
  network::ConnectionProviderState state;
  if (this->component_ == nullptr || this->component_->is_failed())
    return state;
  state.enabled = this->component_->ip_enabled();
  state.connected = state.enabled && this->component_->ip_available();
  if (state.connected) {
    // The ESP32/lwIP adapter exposes its IPv4 address in network byte order.
    // Conversion stays on the mesh side of the generic reporting boundary.
    size_t count = 0;
#ifdef MESH_IPV6
    // IPv6 readiness must not publish an old IPv4 lease whose handover has
    // not completed. Each address family retains its own usability gate.
    if (this->component_->ipv4_available()) {
#endif
      ip4_addr_t address{this->component_->ip_address()};
      if (address.addr != 0)
        state.addresses[count++] = network::IPAddress(&address);
#ifdef MESH_IPV6
    }
    ::mesh_ip::Ipv6AddressSnapshot snapshot;
    if (this->component_->ipv6_snapshot(snapshot) && snapshot.ready) {
      for (size_t i = 0; i < snapshot.count && count < state.addresses.size(); ++i) {
        ip6_addr_t address{};
        std::memcpy(address.addr, snapshot.addresses[i].bytes.data(), 16);
        state.addresses[count++] = network::IPAddress(&address);
      }
    }
#endif
    if (count == 0)
      state.connected = false;
  }
  return state;
}

}  // namespace esphome::mesh
#endif
