#pragma once

#include "mesh_limits.h"

#include "esphome/components/network/connection_provider.h"

#ifdef USE_MESH_IP
namespace esphome::mesh {
class MeshComponent;

// ESPHome-facing reporting adapter. The generic network component knows only
// ConnectionProvider; the mesh's platform netif remains responsible for IP I/O.
class MeshNetworkProvider final : public network::ConnectionProvider {
 public:
  ~MeshNetworkProvider() override { this->stop(); }
  MeshNetworkProvider() = default;
  MeshNetworkProvider(const MeshNetworkProvider &) = delete;
  MeshNetworkProvider &operator=(const MeshNetworkProvider &) = delete;

  bool start(MeshComponent *component);
  void stop();
  network::ConnectionProviderState network_state() const override;

 private:
  MeshComponent *component_{nullptr};
};
}  // namespace esphome::mesh
#endif
