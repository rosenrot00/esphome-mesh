#pragma once

#include "mesh_limits.h"

#include "mesh_transport.h"
#include "mesh_protocol.h"

#include <cstddef>
#include <cstdint>

namespace mesh_core {

using NodeId = uint8_t;
constexpr NodeId kMaxNodes = mesh_limits::MAX_NODES;
constexpr uint8_t kMaxTtl = 8;
constexpr size_t kMaxPayload = mesh_transport::kProtocolPayloadLimit;
constexpr uint32_t kAdvertiseIntervalMs = 250;
constexpr uint32_t kRouteExpiryMs = 2000;
constexpr uint32_t kRouteRequestIntervalMs = 750;
constexpr uint8_t kWireVersion = mesh_protocol::STATIC_FRAME_VERSION;
constexpr uint8_t kSessionWireVersion = mesh_protocol::SESSION_FRAME_VERSION;
constexpr size_t kWireHeaderSize = mesh_transport::kProtocolHeaderSize;
constexpr size_t kSessionWireHeaderSize = mesh_transport::kProtocolSessionHeaderSize;
constexpr size_t kMaxWireSize = kSessionWireHeaderSize + kMaxPayload;

enum class FrameType : uint8_t {
  ADVERTISEMENT = 1,
  PROBE = 2,
  PROBE_REPLY = 3,
  CONTROL = 4,
  DATA = 5,
  ROUTE_REQUEST = 6,
  ROUTE_REPLY = 7,
  BOOT_SESSION = 8,
};

struct Frame {
  FrameType type{FrameType::DATA};
  NodeId source{0};
  NodeId destination{0};  // 0 is used only for advertisements.
  uint16_t sequence{0};
  uint8_t ttl{kMaxTtl};
  NodeId root{0};
  uint8_t rank{255};
  uint16_t path_bits{0};  // Bit (node_id - 1); root-to-advertiser path.
  // Opaque owner/boot epochs. All zero selects the static format; session
  // source/destination/root; transit must preserve these values unchanged.
  uint64_t source_session{0};
  uint64_t destination_session{0};
  uint64_t root_session{0};
  uint16_t payload_length{0};
  uint8_t payload[kMaxPayload]{};
};

// Intervals use unsigned elapsed time on a wrapping millisecond clock. A
// profile changes portable control cadence, not radio duty-cycle compliance.
struct TimingProfile {
  uint32_t advertise_interval_ms{kAdvertiseIntervalMs};
  uint32_t route_expiry_ms{kRouteExpiryMs};
  uint32_t route_request_interval_ms{kRouteRequestIntervalMs};
};
constexpr bool valid_timing_profile(const TimingProfile &profile) {
  return profile.advertise_interval_ms != 0 && profile.advertise_interval_ms < 0x80000000U &&
         profile.route_expiry_ms > profile.advertise_interval_ms && profile.route_expiry_ms < 0x80000000U &&
         profile.route_request_interval_ms != 0 && profile.route_request_interval_ms <= profile.route_expiry_ms;
}

struct RouteSnapshot {
  NodeId parent{0};
  NodeId root{0};
  uint8_t rank{255};
  uint16_t path_bits{0};
  bool connected{false};
  bool direct{false};
  mesh_transport::InterfaceId interface_id{mesh_transport::kNoInterface};
};

struct Counters {
  uint32_t received{0};
  uint32_t forwarded{0};
  uint32_t delivered{0};
  uint32_t duplicate_drops{0};
  uint32_t ttl_drops{0};
  uint32_t invalid_drops{0};
  uint32_t no_route_drops{0};
};

// Callbacks must not synchronously re-enter this same core. send returns true
// only after accepting/copying the complete frame; this is not a delivery ACK.
// False means no copy from this call remains queued: the caller can retry the
// same frame. next_hop == 0 requests fanout to configured peers; its acceptance
// must cover the requested fanout, not a silently accepted subset. The adapter
// implements link/security policy; native radio broadcast is not required.
struct Callbacks {
  void *context{nullptr};
  bool (*send)(void *context, NodeId next_hop, const Frame &frame){nullptr};
  void (*deliver)(void *context, const Frame &frame){nullptr};
  void (*route_changed)(void *context, const RouteSnapshot &route){nullptr};
};

// Explicit byte format: 'M','L',version,type,source,destination,sequence LE16,
// ttl,root,rank,path_bits LE16,payload_length LE16. Version6 appends source,
// destination,root sessions LE64. Version5/6 deliberately reject old3/4 frames;
// exact length and canonical epochs remain required.
constexpr size_t wire_header_size_for_version(uint8_t version) {
  return version == kWireVersion ? kWireHeaderSize : version == kSessionWireVersion ? kSessionWireHeaderSize : 0;
}
constexpr size_t wire_header_size(const Frame &frame) {
  return frame.source_session == 0 ? kWireHeaderSize : kSessionWireHeaderSize;
}
bool validate_frame(const Frame &frame);
bool encode_frame(const Frame &frame, uint8_t *output, size_t capacity, size_t &written);
bool decode_frame(const uint8_t *input, size_t length, Frame &frame);

class MeshCore {
 public:
  explicit MeshCore(NodeId node_id);
  void set_callbacks(const Callbacks &callbacks);
  // Before traffic: null selects strict legacy V1; otherwise every frame must
  // match current opaque sessions. Zero means unknown/unadmitted. The resolver
  // must not re-enter the core and must stay stable during each core call.
  using SessionResolver = uint64_t (*)(void *, NodeId);
  bool set_session_resolver(void *context, SessionResolver resolver);
  // Manual bootstrap is a separate canonical flood, never ordinary unscoped
  // traffic. Automatic membership and legacy callers leave this disabled.
  bool set_bootstrap_allowed(bool allowed);
  bool send_bootstrap(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length, uint32_t now_ms);
  // Bind exactly one transport interface. Rebinding to a different interface
  // ID after any mesh traffic is rejected; bind before receiving or ticking.
  // Multiple simultaneous radios need explicit routing support.
  // Legacy callbacks.send remains available when no transport is bound.
  bool set_transport(const mesh_transport::Transport &transport);
  mesh_transport::InterfaceId interface_id() const { return interface_id_; }
  bool set_timing_profile(const TimingProfile &profile);
  const TimingProfile &timing_profile() const { return timing_; }
  // Invalid declarations leave the previous contract unchanged. A bound
  // adapter owns its declared MTU; configure it before binding the transport.
  bool set_link_capabilities(const mesh_transport::LinkCapabilities &link);
  const mesh_transport::LinkCapabilities &link_capabilities() const { return link_; }
  void tick(uint32_t now_ms);
  void receive(NodeId immediate_sender, const Frame &frame, uint32_t now_ms);
  void receive(const mesh_transport::ReceiveMetadata &metadata, const Frame &frame, uint32_t now_ms);
  void set_direct_uplink(bool available, uint32_t now_ms);
  // Optional legacy root preference before path length. The endpoint adapter
  // leaves this disabled: native uplinks stay local, clients choose nearest.
  void set_prefer_root_id(bool enabled) { prefer_root_id_ = enabled; }
  // By default, keep a valid current parent/root at equal hop cost and switch
  // for a shorter mesh path. Enabling stability also keeps a valid longer
  // mesh path until unusable; native exits stay local in either mode.
  void set_route_stability(bool enabled) { route_stability_ = enabled; }
  // An unknown unicast destination starts bounded on-demand discovery and
  // returns false. No application frame is buffered; its caller must retry.
  bool send_probe(NodeId destination, uint16_t sequence, uint32_t now_ms);
  // Echo probes carry 0..kMaxPayload bytes, returned unchanged in PROBE_REPLY.
  bool send_probe_payload(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                          uint32_t now_ms);
  bool send_control(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length, uint32_t now_ms);
  bool send_data(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length, uint32_t now_ms);
  bool originate(Frame frame, uint32_t now_ms);

  NodeId node_id() const { return node_id_; }
  const RouteSnapshot &route() const { return route_; }
  const Counters &counters() const { return counters_; }

 private:
  struct Neighbor {
    bool seen{false};
    uint32_t last_seen{0};
    uint16_t sequence{0};
    NodeId root{0};
    uint8_t rank{255};
    uint16_t path_bits{0};
    uint64_t source_session{0}, root_session{0};
  };
  struct LearnedRoute {
    NodeId next_hop{0};
    uint32_t last_seen{0};
    uint16_t sequence{0};
    uint8_t distance{0};
    bool discovery{false};
    uint64_t source_session{0}, next_hop_session{0};
  };
  struct SeenFrame {
    bool used{false};
    NodeId source{0};
    NodeId destination{0};
    FrameType type{FrameType::DATA};
    uint16_t sequence{0};
    uint32_t seen_at{0};
    uint64_t source_session{0}, destination_session{0}, root_session{0};
  };
  struct RouteRequest {
    bool sent{false};
    uint32_t last_accepted{0};
  };
  static constexpr size_t kDedupSlots = 32;

  bool valid_id(NodeId id) const;
  uint64_t session(NodeId id) const;
  bool bind_local(Frame &frame) const;
  bool sessions_match(const Frame &frame) const;
  bool neighbor_current(NodeId id, const Neighbor &neighbor) const;
  bool learned_current(NodeId id, const LearnedRoute &learned) const;
  void select_route(uint32_t now_ms);
  void advertise(uint32_t now_ms);
  NodeId next_hop(NodeId destination, NodeId avoid, uint32_t now_ms) const;
  bool seen_before(const Frame &frame, uint32_t now_ms);
  void remember(const Frame &frame, uint32_t now_ms);
  bool emit(NodeId next_hop, const Frame &frame, uint32_t now_ms);
  void request_route(NodeId destination, uint32_t now_ms);
  void receive_route_request(NodeId immediate_sender, const Frame &frame, uint32_t now_ms);
  void learn_source(NodeId immediate_sender, const Frame &frame, uint32_t now_ms);
  bool send_payload(FrameType type, NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                    uint32_t now_ms);
  // Internal callers already own their frame; the public originate() keeps its
  // by-value contract so application-owned frames are never modified.
  bool originate_owned_(Frame &frame, uint32_t now_ms);
  void deliver_local(const Frame &frame, uint32_t now_ms);

  NodeId node_id_;
  Callbacks callbacks_{};
  mesh_transport::LinkCapabilities link_{};
  void *transport_context_{nullptr};
  bool (*transport_enqueue_)(void *, mesh_transport::InterfaceId, uint8_t, const Frame &, uint32_t){nullptr};
  mesh_transport::InterfaceId interface_id_{mesh_transport::kDefaultInterface};
  TimingProfile timing_{};
  RouteSnapshot route_{};
  Counters counters_{};
  Neighbor neighbors_[kMaxNodes + 1]{};
  LearnedRoute learned_[kMaxNodes + 1]{};
  SeenFrame seen_[kDedupSlots]{};
  RouteRequest requests_[kMaxNodes]{};
  size_t seen_cursor_{0};
  uint16_t advertisement_sequence_{0};
  uint16_t discovery_sequence_{0};
  uint32_t last_advertised_{0};
  bool advertised_once_{false};
  bool advertisement_pending_{true};
  bool direct_uplink_{false};
  bool prefer_root_id_{false};
  bool route_stability_{false};
  void *session_context_{nullptr};
  SessionResolver session_resolver_{nullptr};
  bool session_mode_locked_{false};
  bool bootstrap_allowed_{false};
};

}  // namespace mesh_core
