#include "mesh_runtime.h"

namespace mesh_core {

MeshRuntime::MeshRuntime(NodeId node_id) : core_(node_id) {
  core_.set_callbacks({this, nullptr, deliver_, route_changed_});
}

bool MeshRuntime::bind(const mesh_transport::Transport &transport, const TimingProfile &timing,
                       const Observers &observers, size_t control_payload_budget) {
  if (configured_ || !mesh_transport::valid_transport(transport, true) || !valid_timing_profile(timing) ||
      !mesh_transport::supports_control_budget(transport.interface.capabilities, control_payload_budget))
    return false;
  if (!core_.set_transport(transport) || !core_.set_timing_profile(timing))
    return false;
  transport_ = transport;
  observers_ = observers;
  configured_ = true;
  return true;
}

bool MeshRuntime::start() {
  return configured_ && (transport_.start == nullptr || transport_.start(transport_.context));
}

void MeshRuntime::stop() {
  if (configured_ && transport_.stop != nullptr)
    transport_.stop(transport_.context);
}

void MeshRuntime::set_wake_callback(void *context, mesh_transport::WakeCallback callback) {
  if (configured_ && transport_.set_wake_callback != nullptr)
    transport_.set_wake_callback(transport_.context, context, callback);
}

size_t MeshRuntime::poll(uint32_t now_ms, size_t budget) {
  if (!configured_)
    return 0;
  size_t processed = 0;
  for (; processed < budget; ++processed) {
    mesh_transport::ReceiveMetadata metadata;
    Frame frame;
    if (!mesh_transport::poll_receive_checked(transport_, metadata, frame))
      break;
    if (observers_.accept != nullptr && !observers_.accept(observers_.context, metadata, frame)) {
      ++counters_.policy_drops;
      continue;
    }
    core_.receive(metadata, frame, now_ms);
    ++counters_.accepted_input;
    if (observers_.received != nullptr)
      observers_.received(observers_.context, now_ms);
  }
  return processed;
}

void MeshRuntime::tick(uint32_t now_ms) {
  if (configured_)
    core_.tick(now_ms);
}

void MeshRuntime::process(uint32_t now_ms, bool allow_start) {
  if (configured_ && transport_.process != nullptr)
    transport_.process(transport_.context, now_ms, allow_start);
}

void MeshRuntime::cancel_pending(bool keep_inflight) {
  if (configured_ && transport_.cancel_pending != nullptr)
    transport_.cancel_pending(transport_.context, keep_inflight);
}

void MeshRuntime::discard_receive() {
  if (configured_ && transport_.discard_receive != nullptr)
    transport_.discard_receive(transport_.context);
}

mesh_transport::QueueState MeshRuntime::queue_state() const {
  return configured_ && transport_.queue_state != nullptr ? transport_.queue_state(transport_.context)
                                                          : mesh_transport::QueueState{};
}

mesh_transport::TransportCounters MeshRuntime::transport_counters() const {
  return configured_ && transport_.counters != nullptr ? transport_.counters(transport_.context)
                                                       : mesh_transport::TransportCounters{};
}

void MeshRuntime::deliver_(void *context, const Frame &frame) {
  auto *self = static_cast<MeshRuntime *>(context);
  if (self->observers_.deliver != nullptr)
    self->observers_.deliver(self->observers_.context, frame);
}

void MeshRuntime::route_changed_(void *context, const RouteSnapshot &route) {
  auto *self = static_cast<MeshRuntime *>(context);
  if (self->observers_.route_changed != nullptr)
    self->observers_.route_changed(self->observers_.context, route);
}

}  // namespace mesh_core
