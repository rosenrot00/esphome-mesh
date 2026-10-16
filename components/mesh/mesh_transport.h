#pragma once

#include "mesh_limits.h"

#include <cstddef>
#include <cstdint>

namespace mesh_core {
struct Frame;
}

namespace mesh_transport {

using InterfaceId = uint8_t;
using WakeCallback = void (*)(void *);
constexpr InterfaceId kNoInterface = 0;
constexpr InterfaceId kDefaultInterface = 1;

// Limits of this mesh wire protocol, independent of any radio's native MTU.
// A transport with larger frames does not silently enlarge protocol buffers.
constexpr size_t kProtocolHeaderSize = 15;
constexpr size_t kProtocolSessionHeaderSize = kProtocolHeaderSize + 3 * sizeof(uint64_t);
constexpr size_t kProtocolPayloadLimit = mesh_limits::PROTOCOL_PAYLOAD_BUDGET;
constexpr size_t kProtocolControlPayloadLimit = 160;
static_assert(kProtocolSessionHeaderSize + kProtocolPayloadLimit == mesh_limits::NATIVE_FRAME_BUDGET,
              "Native frame budget must include the complete session header");
constexpr size_t kProtocolFrameLimit = kProtocolSessionHeaderSize + kProtocolPayloadLimit;

struct LinkCapabilities {
  // Maximum mesh payload accepted by this adapter, excluding the mesh
  // header and its own framing. Larger DATA frames use native ESP-NOW v2;
  // other links remain bounded by their own capability.
  size_t payload_mtu{kProtocolPayloadLimit};
  // True declares a link guarantee, not successful delivery of a queued send.
  // False means that the portable core cannot rely on that guarantee.
  bool reliable_unicast{false};
  bool native_broadcast{false};
  bool reliable_broadcast{false};
  bool security_provided{false};  // Authenticated encryption on this link only.
  // Optional planning hints: zero is unspecified, not unlimited or zero cost.
  // They do not enable rate control, duty-cycle compliance, or new route metrics.
  uint32_t sustainable_bitrate_bps{0};
  uint16_t airtime_budget_permille{0};
  // Optional adapter-defined channel numbers; no Wi-Fi numbering is assumed.
  bool channel_selection_supported{false};
  uint16_t first_channel{0};
  uint16_t last_channel{0};
};

constexpr bool valid_link_capabilities(const LinkCapabilities &link) {
  return link.payload_mtu != 0 && link.airtime_budget_permille <= 1000 &&
         (!link.reliable_broadcast || link.native_broadcast) &&
         (link.channel_selection_supported ? link.last_channel >= link.first_channel
                                           : link.first_channel == 0 && link.last_channel == 0);
}

constexpr bool validates_frame_budget(const LinkCapabilities &link, size_t payload_length) {
  return valid_link_capabilities(link) && payload_length <= kProtocolPayloadLimit && payload_length <= link.payload_mtu;
}

// Derive an adapter's payload MTU from its complete frame budget. Subtraction
// avoids overflow even for untrusted/exaggerated capabilities. Zero cannot
// carry nonempty mesh control/data and is rejected by set_link_capabilities().
constexpr size_t payload_mtu_for_frame_budget(size_t frame_mtu, size_t adapter_overhead = 0,
                                              size_t header_size = kProtocolHeaderSize) {
  if ((header_size != kProtocolHeaderSize && header_size != kProtocolSessionHeaderSize) || frame_mtu < header_size ||
      adapter_overhead > frame_mtu - header_size)
    return 0;
  const size_t payload_mtu = frame_mtu - header_size - adapter_overhead;
  return payload_mtu < kProtocolPayloadLimit ? payload_mtu : kProtocolPayloadLimit;
}

constexpr bool validates_frame_budget(const LinkCapabilities &link, size_t payload_length, size_t frame_mtu,
                                      size_t adapter_overhead = 0, size_t header_size = kProtocolHeaderSize) {
  return validates_frame_budget(link, payload_length) &&
         (header_size == kProtocolHeaderSize || header_size == kProtocolSessionHeaderSize) &&
         frame_mtu >= header_size && adapter_overhead <= frame_mtu - header_size &&
         payload_length <= frame_mtu - header_size - adapter_overhead;
}

// IP endpoint controls are not fragmented by the IP packet fragmenter. Reject
// a transport too small for the whole endpoint protocol before activating it.
constexpr size_t kEndpointControlPayloadBudget = 43;
constexpr bool supports_control_budget(const LinkCapabilities &link,
                                       size_t required_payload = kEndpointControlPayloadBudget) {
  return validates_frame_budget(link, required_payload);
}

struct InterfaceDescriptor {
  InterfaceId id{kDefaultInterface};
  LinkCapabilities capabilities{};
};
constexpr bool valid_interface(const InterfaceDescriptor &interface) {
  return interface.id != kNoInterface && valid_link_capabilities(interface.capabilities);
}

// Adapter-local reception metadata. The adapter authenticates/configures the
// immediate peer; the portable core still validates its ID and frame fields.
// Channel is informational and has no assumed Wi-Fi units or route metric.
struct ReceiveMetadata {
  InterfaceId interface_id{kDefaultInterface};
  uint8_t immediate_sender{0};
  uint16_t channel{0};
};
struct QueueState {
  size_t pending{0};
  size_t capacity{0};
  bool inflight{false};
};
struct TransportCounters {
  uint32_t accepted{0};
  uint32_t rejected{0};
  uint32_t sent{0};
  uint32_t failed{0};
  uint32_t received{0};
  uint32_t receive_drops{0};
  uint32_t transmit_drops{0};  // Adapter drops, including admission/expiry/callback failures.
};

// One active interface per runtime/core. No allocation, inheritance or SDK
// types: a platform adapter exports this function table and keeps its state.
// All calls are serialized by the runtime. Adapter callbacks must not re-enter
// it. enqueue returns true only for complete local queue admission, including
// all configured peers when next_hop==0; false retains no copy from that call.
// This is NOT an over-the-air delivery ACK. poll_receive consumes at most one
// decoded frame and can discard bounded invalid adapter records internally.
struct Transport {
  void *context{nullptr};
  InterfaceDescriptor interface {};
  bool (*enqueue)(void *, InterfaceId, uint8_t next_hop, const mesh_core::Frame &, uint32_t now_ms){nullptr};
  bool (*poll_receive)(void *, ReceiveMetadata &, mesh_core::Frame &){nullptr};
  void (*process)(void *, uint32_t now_ms, bool allow_start){nullptr};
  bool (*start)(void *){nullptr};
  void (*stop)(void *){nullptr};
  void (*cancel_pending)(void *, bool keep_inflight){nullptr};
  void (*discard_receive)(void *){nullptr};
  QueueState (*queue_state)(const void *){nullptr};
  TransportCounters (*counters)(const void *){nullptr};
  // Optional nonblocking scheduling hint. May run on a driver's callback task;
  // never re-enter the runtime. Context outlives in-progress notifications.
  void (*set_wake_callback)(void *, void *wake_context, WakeCallback){nullptr};
};

// Lifecycle/service/statistics hooks are optional. An active transport needs
// enqueue; a runtime that pumps input additionally requires poll_receive.
bool valid_transport(const Transport &transport, bool require_receive = false);
bool enqueue_checked(const Transport &transport, uint8_t next_hop, const mesh_core::Frame &frame, uint32_t now_ms);
bool poll_receive_checked(const Transport &transport, ReceiveMetadata &metadata, mesh_core::Frame &frame);

}  // namespace mesh_transport
