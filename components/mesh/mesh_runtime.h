#pragma once

#include "mesh_limits.h"

#include "mesh_core.h"

#include <cstddef>
#include <cstdint>

namespace mesh_core {

// Serialized portable coordinator. A platform supplies the adapter and clock;
// it owns scheduling, locking, native uplinks and IP services. The runtime
// pumps decoded input and routing without knowing any radio SDK or RTOS.
class MeshRuntime {
 public:
  struct Observers {
    void *context{nullptr};
    bool (*accept)(void *, const mesh_transport::ReceiveMetadata &, const Frame &){nullptr};
    void (*deliver)(void *, const Frame &){nullptr};
    void (*route_changed)(void *, const RouteSnapshot &){nullptr};
    void (*received)(void *, uint32_t now_ms){nullptr};
  };
  struct Counters {
    uint32_t accepted_input{0};
    uint32_t policy_drops{0};
  };

  explicit MeshRuntime(NodeId node_id);
  // Bind once, before use. A failed bind leaves the runtime unconfigured.
  // The endpoint budget applies to unfragmented control messages. A transport
  // too small for them must implement a control adaptation before binding.
  bool bind(const mesh_transport::Transport &transport, const TimingProfile &timing, const Observers &observers,
            size_t control_payload_budget = 0);
  bool start();
  void stop();
  void set_wake_callback(void *context, mesh_transport::WakeCallback callback);
  size_t poll(uint32_t now_ms, size_t budget);
  void tick(uint32_t now_ms);
  void process(uint32_t now_ms, bool allow_start = true);
  void cancel_pending(bool keep_inflight = true);
  void discard_receive();
  mesh_transport::QueueState queue_state() const;
  mesh_transport::TransportCounters transport_counters() const;
  MeshCore &core() { return core_; }
  const MeshCore &core() const { return core_; }
  const Counters &counters() const { return counters_; }
  bool configured() const { return configured_; }
  const mesh_transport::InterfaceDescriptor &interface() const { return transport_.interface; }

 private:
  static void deliver_(void *context, const Frame &frame);
  static void route_changed_(void *context, const RouteSnapshot &route);
  MeshCore core_;
  mesh_transport::Transport transport_{};
  Observers observers_{};
  Counters counters_{};
  bool configured_{false};
};

}  // namespace mesh_core
