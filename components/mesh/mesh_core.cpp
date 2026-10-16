#include "mesh_core.h"
#include "mesh_session.h"

namespace mesh_core {
namespace {

bool id_valid(NodeId id) { return id >= 1 && id <= kMaxNodes; }
uint16_t node_bit(NodeId id) { return id_valid(id) ? static_cast<uint16_t>(1U << (id - 1)) : 0; }
bool expired(uint32_t now, uint32_t then, uint32_t timeout) { return static_cast<uint32_t>(now - then) >= timeout; }
uint8_t bit_count(uint16_t value) {
  uint8_t count = 0;
  while (value != 0) {
    count += value & 1U;
    value >>= 1;
  }
  return count;
}
bool newer_sequence(uint16_t value, uint16_t previous) {
  const uint16_t distance = static_cast<uint16_t>(value - previous);
  return distance != 0 && distance < 0x8000U;
}
uint64_t dedup_source_session(const Frame &frame) {
  if (frame.type != FrameType::BOOT_SESSION)
    return frame.source_session;
  mesh_session::Message message;
  return mesh_session::decode(frame.payload, frame.payload_length, frame.source, frame.destination, message)
             ? message.source_boot
             : 0;
}
bool frame_valid(const Frame &frame) {
  if (!id_valid(frame.source) || frame.ttl == 0 || frame.ttl > kMaxTtl || frame.payload_length > kMaxPayload ||
      (frame.type != FrameType::DATA && frame.payload_length > mesh_transport::kProtocolControlPayloadLimit))
    return false;
  const bool scoped = frame.source_session != 0;
  if ((!scoped && (frame.destination_session != 0 || frame.root_session != 0)) ||
      (scoped && ((frame.destination != 0) != (frame.destination_session != 0) ||
                  (frame.root != 0) != (frame.root_session != 0) ||
                  (frame.source == frame.destination && frame.source_session != frame.destination_session) ||
                  (frame.source == frame.root && frame.source_session != frame.root_session))))
    return false;
  const auto type = static_cast<uint8_t>(frame.type);
  if (type < static_cast<uint8_t>(FrameType::ADVERTISEMENT) || type > static_cast<uint8_t>(FrameType::BOOT_SESSION))
    return false;
  if (frame.type == FrameType::BOOT_SESSION) {
    mesh_session::Message message;
    return !scoped && frame.root == 0 && frame.rank == 255 && frame.path_bits == 0 &&
           mesh_session::decode(frame.payload, frame.payload_length, frame.source, frame.destination, message);
  }
  if (frame.type == FrameType::ADVERTISEMENT) {
    if (frame.destination != 0 || frame.payload_length != 0)
      return false;
    if (frame.root == 0)
      return frame.rank == 255 && frame.path_bits == 0;
    if (!id_valid(frame.root) || frame.rank > kMaxTtl || (frame.path_bits & ~mesh_limits::ID_MASK) != 0 ||
        bit_count(frame.path_bits) != frame.rank + 1 || (frame.path_bits & node_bit(frame.source)) == 0 ||
        (frame.path_bits & node_bit(frame.root)) == 0)
      return false;
    return (frame.rank == 0) == (frame.source == frame.root);
  }
  if (!id_valid(frame.destination) || frame.root != 0 || frame.rank != 255 || frame.path_bits != 0)
    return false;
  if ((frame.type == FrameType::ROUTE_REQUEST || frame.type == FrameType::ROUTE_REPLY) &&
      (frame.payload_length != 0 || frame.source == frame.destination))
    return false;
  return true;
}
bool same_route(const RouteSnapshot &a, const RouteSnapshot &b) {
  return a.parent == b.parent && a.root == b.root && a.rank == b.rank && a.path_bits == b.path_bits &&
         a.connected == b.connected && a.direct == b.direct && a.interface_id == b.interface_id;
}

}  // namespace

bool validate_frame(const Frame &frame) { return frame_valid(frame); }

bool encode_frame(const Frame &frame, uint8_t *output, size_t capacity, size_t &written) {
  written = 0;
  const size_t header = wire_header_size(frame);
  const size_t length = header + frame.payload_length;
  if (output == nullptr || !frame_valid(frame) || capacity < length)
    return false;
  output[0] = 'M';
  output[1] = 'L';
  output[2] = frame.source_session == 0 ? kWireVersion : kSessionWireVersion;
  output[3] = static_cast<uint8_t>(frame.type);
  output[4] = frame.source;
  output[5] = frame.destination;
  output[6] = static_cast<uint8_t>(frame.sequence);
  output[7] = static_cast<uint8_t>(frame.sequence >> 8);
  output[8] = frame.ttl;
  output[9] = frame.root;
  output[10] = frame.rank;
  output[11] = static_cast<uint8_t>(frame.path_bits);
  output[12] = static_cast<uint8_t>(frame.path_bits >> 8);
  output[13] = static_cast<uint8_t>(frame.payload_length);
  output[14] = static_cast<uint8_t>(frame.payload_length >> 8);
  if (frame.source_session != 0) {
    const uint64_t sessions[]{frame.source_session, frame.destination_session, frame.root_session};
    for (size_t tag = 0; tag < 3; ++tag)
      for (size_t byte = 0; byte < 8; ++byte)
        output[kWireHeaderSize + tag * 8 + byte] = static_cast<uint8_t>(sessions[tag] >> (byte * 8));
  }
  for (size_t i = 0; i < frame.payload_length; ++i)
    output[header + i] = frame.payload[i];
  written = length;
  return true;
}

bool decode_frame(const uint8_t *input, size_t length, Frame &frame) {
  if (input == nullptr || length < kWireHeaderSize || length > kMaxWireSize || input[0] != 'M' || input[1] != 'L')
    return false;
  const size_t header = wire_header_size_for_version(input[2]);
  const uint16_t payload_length = static_cast<uint16_t>(input[13] | (uint16_t(input[14]) << 8));
  if (header == 0 || length < header || payload_length > kMaxPayload || length != header + payload_length)
    return false;
  Frame decoded{};
  decoded.type = static_cast<FrameType>(input[3]);
  decoded.source = input[4];
  decoded.destination = input[5];
  decoded.sequence = static_cast<uint16_t>(input[6] | (input[7] << 8));
  decoded.ttl = input[8];
  decoded.root = input[9];
  decoded.rank = input[10];
  decoded.path_bits = static_cast<uint16_t>(input[11] | (input[12] << 8));
  decoded.payload_length = payload_length;
  if (input[2] == kSessionWireVersion) {
    uint64_t *sessions[]{&decoded.source_session, &decoded.destination_session, &decoded.root_session};
    for (size_t tag = 0; tag < 3; ++tag)
      for (size_t byte = 0; byte < 8; ++byte)
        *sessions[tag] |= uint64_t(input[kWireHeaderSize + tag * 8 + byte]) << (byte * 8);
    if (decoded.source_session == 0)
      return false;
  }
  for (size_t i = 0; i < decoded.payload_length; ++i)
    decoded.payload[i] = input[header + i];
  if (!frame_valid(decoded))
    return false;
  frame = decoded;
  return true;
}

MeshCore::MeshCore(NodeId node_id) : node_id_(node_id) {}

void MeshCore::set_callbacks(const Callbacks &callbacks) { callbacks_ = callbacks; }

bool MeshCore::set_session_resolver(void *context, SessionResolver resolver) {
  if (session_mode_locked_)
    return false;
  session_context_ = context;
  session_resolver_ = resolver;
  return true;
}

bool MeshCore::set_bootstrap_allowed(bool allowed) {
  if (session_mode_locked_ || (allowed && session_resolver_ == nullptr))
    return false;
  bootstrap_allowed_ = allowed;
  return true;
}

uint64_t MeshCore::session(NodeId id) const {
  return session_resolver_ != nullptr && valid_id(id) ? session_resolver_(session_context_, id) : 0;
}

bool MeshCore::bind_local(Frame &frame) const {
  frame.source_session = session(node_id_);
  frame.destination_session = session(frame.destination);
  frame.root_session = session(frame.root);
  return sessions_match(frame);
}

bool MeshCore::sessions_match(const Frame &frame) const {
  if (frame.type == FrameType::BOOT_SESSION)
    return bootstrap_allowed_ && frame.source_session == 0 && frame.destination_session == 0 && frame.root_session == 0;
  if (session_resolver_ == nullptr)
    return frame.source_session == 0 && frame.destination_session == 0 && frame.root_session == 0;
  if (frame.source_session == 0 || frame.source_session != session(frame.source))
    return false;
  if (frame.destination == 0
          ? frame.destination_session != 0
          : frame.destination_session == 0 || frame.destination_session != session(frame.destination))
    return false;
  return frame.root == 0 ? frame.root_session == 0
                         : frame.root_session != 0 && frame.root_session == session(frame.root);
}

bool MeshCore::neighbor_current(NodeId id, const Neighbor &neighbor) const {
  return neighbor.source_session == session(id) &&
         (neighbor.root == 0 ? neighbor.root_session == 0 : neighbor.root_session == session(neighbor.root)) &&
         (session_resolver_ == nullptr ||
          (neighbor.source_session != 0 && (neighbor.root == 0 || neighbor.root_session != 0)));
}

bool MeshCore::learned_current(NodeId id, const LearnedRoute &learned) const {
  return learned.source_session == session(id) && learned.next_hop_session == session(learned.next_hop) &&
         (session_resolver_ == nullptr || (learned.source_session != 0 && learned.next_hop_session != 0));
}

bool MeshCore::set_transport(const mesh_transport::Transport &transport) {
  if (!mesh_transport::valid_transport(transport) ||
      (transport.interface.id != interface_id_ &&
       (transport_enqueue_ != nullptr || counters_.received != 0 || advertised_once_)))
    return false;
  transport_context_ = transport.context;
  transport_enqueue_ = transport.enqueue;
  interface_id_ = transport.interface.id;
  link_ = transport.interface.capabilities;
  return true;
}

bool MeshCore::set_timing_profile(const TimingProfile &profile) {
  if (!valid_timing_profile(profile))
    return false;
  timing_ = profile;
  return true;
}

bool MeshCore::set_link_capabilities(const mesh_transport::LinkCapabilities &link) {
  if (transport_enqueue_ != nullptr || !mesh_transport::valid_link_capabilities(link))
    return false;
  link_ = link;
  return true;
}

bool MeshCore::valid_id(NodeId id) const { return id_valid(id); }

void MeshCore::select_route(uint32_t now_ms) {
  RouteSnapshot selected{};
  if (valid_id(node_id_) && direct_uplink_ && (session_resolver_ == nullptr || session(node_id_) != 0)) {
    selected.root = node_id_;
    selected.rank = 0;
    selected.path_bits = node_bit(node_id_);
    selected.connected = true;
    selected.direct = true;
  }
  for (NodeId id = 1; id <= kMaxNodes; ++id) {
    auto &neighbor = neighbors_[id];
    if (neighbor.seen &&
        (expired(now_ms, neighbor.last_seen, timing_.route_expiry_ms) || !neighbor_current(id, neighbor)))
      neighbor.seen = false;
    if (learned_[id].next_hop != 0 &&
        (expired(now_ms, learned_[id].last_seen, timing_.route_expiry_ms) || !learned_current(id, learned_[id])))
      learned_[id] = LearnedRoute{};
    if ((selected.direct && !prefer_root_id_) || !neighbor.seen || neighbor.root == 0 || neighbor.rank >= kMaxTtl ||
        (neighbor.path_bits & node_bit(node_id_)) != 0)
      continue;
    const uint8_t rank = neighbor.rank + 1;
    if (selected.connected) {
      // The normal policy favors the nearest uplink and retains a native exit.
      // Optional legacy root preference selects the lowest reachable root;
      // paths to the same root still use shortest path/lowest parent.
      if (prefer_root_id_) {
        if (neighbor.root > selected.root || (neighbor.root == selected.root && rank > selected.rank) ||
            (neighbor.root == selected.root && rank == selected.rank && id >= selected.parent))
          continue;
      } else if (rank > selected.rank || (rank == selected.rank && neighbor.root > selected.root) ||
                 (rank == selected.rank && neighbor.root == selected.root && id >= selected.parent)) {
        continue;
      }
    }
    selected.parent = id;
    selected.root = neighbor.root;
    selected.rank = rank;
    selected.path_bits = neighbor.path_bits | node_bit(node_id_);
    selected.connected = true;
    selected.direct = false;
  }
  if (!prefer_root_id_ && !selected.direct && route_.connected && !route_.direct && valid_id(route_.parent)) {
    const auto &current = neighbors_[route_.parent];
    // Revalidate against this parent's latest advertisement. Retaining an
    // obsolete snapshot would preserve loops or a withdrawn root.
    // Shortest mode keeps equal-cost paths; stable mode also keeps a usable
    // current path when another mesh path becomes shorter.
    if (current.seen && neighbor_current(route_.parent, current) &&
        !expired(now_ms, current.last_seen, timing_.route_expiry_ms) && current.root != 0 &&
        current.root == route_.root && current.rank < kMaxTtl && (current.path_bits & node_bit(node_id_)) == 0 &&
        (route_stability_ || static_cast<uint8_t>(current.rank + 1) <= selected.rank)) {
      selected = RouteSnapshot{route_.parent,
                               current.root,
                               static_cast<uint8_t>(current.rank + 1),
                               static_cast<uint16_t>(current.path_bits | node_bit(node_id_)),
                               true,
                               false};
    }
  }
  selected.interface_id = selected.connected && !selected.direct ? interface_id_ : mesh_transport::kNoInterface;
  if (!same_route(selected, route_)) {
    route_ = selected;
    advertisement_pending_ = true;
    if (callbacks_.route_changed != nullptr)
      callbacks_.route_changed(callbacks_.context, route_);
  }
}

void MeshCore::set_direct_uplink(bool available, uint32_t now_ms) {
  direct_uplink_ = available;
  select_route(now_ms);
}

bool MeshCore::emit(NodeId hop, const Frame &frame, uint32_t now_ms) {
  if (!frame_valid(frame) || !sessions_match(frame))
    return false;
  if (transport_enqueue_ != nullptr) {
    if (!frame_valid(frame) || !mesh_transport::validates_frame_budget(link_, frame.payload_length))
      return false;
    return transport_enqueue_(transport_context_, interface_id_, hop, frame, now_ms);
  }
  if (callbacks_.send == nullptr || !mesh_transport::validates_frame_budget(link_, frame.payload_length))
    return false;
  return callbacks_.send(callbacks_.context, hop, frame);
}

void MeshCore::advertise(uint32_t now_ms) {
  if (!valid_id(node_id_))
    return;
  Frame frame{};
  frame.type = FrameType::ADVERTISEMENT;
  frame.source = node_id_;
  frame.sequence = static_cast<uint16_t>(advertisement_sequence_ + 1);
  frame.root = route_.root;
  frame.rank = route_.rank;
  frame.path_bits = route_.path_bits;
  if (!bind_local(frame) || !emit(0, frame, now_ms)) {
    advertisement_pending_ = true;
    return;
  }
  advertisement_sequence_ = frame.sequence;
  last_advertised_ = now_ms;
  advertised_once_ = true;
  advertisement_pending_ = false;
}

void MeshCore::tick(uint32_t now_ms) {
  session_mode_locked_ = true;
  select_route(now_ms);
  if (!advertised_once_ || advertisement_pending_ ||
      static_cast<uint32_t>(now_ms - last_advertised_) >= timing_.advertise_interval_ms)
    advertise(now_ms);
}

NodeId MeshCore::next_hop(NodeId destination, NodeId avoid, uint32_t now_ms) const {
  if (!valid_id(destination))
    return 0;
  if (destination != avoid && neighbors_[destination].seen &&
      !expired(now_ms, neighbors_[destination].last_seen, timing_.route_expiry_ms))
    return destination;
  if (destination == route_.root && route_.parent != 0 && route_.parent != avoid)
    return route_.parent;
  const auto &learned = learned_[destination];
  if (learned.next_hop != 0 && learned.next_hop != avoid &&
      !expired(now_ms, learned.last_seen, timing_.route_expiry_ms) && neighbors_[learned.next_hop].seen &&
      !expired(now_ms, neighbors_[learned.next_hop].last_seen, timing_.route_expiry_ms))
    return learned.next_hop;
  return 0;
}

void MeshCore::request_route(NodeId destination, uint32_t now_ms) {
  if (!valid_id(destination) || destination == node_id_)
    return;
  auto &request = requests_[destination - 1];
  if (request.sent && uint32_t(now_ms - request.last_accepted) < timing_.route_request_interval_ms)
    return;
  Frame frame{};
  frame.type = FrameType::ROUTE_REQUEST;
  frame.source = node_id_;
  frame.destination = destination;
  frame.sequence = static_cast<uint16_t>(discovery_sequence_ + 1);
  if (!bind_local(frame) || !emit(0, frame, now_ms))
    return;
  discovery_sequence_ = frame.sequence;
  request.sent = true;
  request.last_accepted = now_ms;
  remember(frame, now_ms);
}

void MeshCore::receive_route_request(NodeId immediate_sender, const Frame &frame, uint32_t now_ms) {
  if (frame.destination == node_id_) {
    Frame reply{};
    reply.type = FrameType::ROUTE_REPLY;
    reply.source = node_id_;
    reply.destination = frame.source;
    // Replies have a target-owned sequence. Concurrent requesters may use
    // identical request numbers, and must never suppress each other's reply.
    reply.sequence = static_cast<uint16_t>(discovery_sequence_ + 1);
    if (bind_local(reply) && emit(immediate_sender, reply, now_ms)) {
      discovery_sequence_ = reply.sequence;
      remember(frame, now_ms);
      remember(reply, now_ms);
    }
    return;
  }
  if (frame.ttl <= 1) {
    ++counters_.ttl_drops;
    return;
  }
  Frame forwarded = frame;
  --forwarded.ttl;
  if (emit(0, forwarded, now_ms)) {
    remember(frame, now_ms);
    ++counters_.forwarded;
  }
}

void MeshCore::learn_source(NodeId immediate_sender, const Frame &frame, uint32_t now_ms) {
  auto &learned = learned_[frame.source];
  const bool discovery = frame.type == FrameType::ROUTE_REQUEST || frame.type == FrameType::ROUTE_REPLY;
  if (!discovery)
    return;
  const bool fresh = learned.next_hop != 0 && !expired(now_ms, learned.last_seen, timing_.route_expiry_ms);
  const uint8_t distance = static_cast<uint8_t>(kMaxTtl - frame.ttl + 1);
  if (fresh && learned.discovery) {
    // Internal discovery counters belong to the source (unlike probe echo
    // numbers). Old floods and ordinary traffic cannot overwrite or prolong
    // a newer path and create a cycle between overlapping searches.
    if (!newer_sequence(frame.sequence, learned.sequence) &&
        (frame.sequence != learned.sequence || distance >= learned.distance))
      return;
  }
  learned = LearnedRoute{immediate_sender,         now_ms, frame.sequence, distance, discovery, frame.source_session,
                         session(immediate_sender)};
}

bool MeshCore::seen_before(const Frame &frame, uint32_t now_ms) {
  const uint64_t source_session = dedup_source_session(frame);
  for (const auto &entry : seen_) {
    if (entry.used && !expired(now_ms, entry.seen_at, timing_.route_expiry_ms) && entry.source == frame.source &&
        entry.destination == frame.destination && entry.type == frame.type && entry.sequence == frame.sequence &&
        entry.source_session == source_session && entry.destination_session == frame.destination_session &&
        entry.root_session == frame.root_session)
      return true;
  }
  return false;
}

void MeshCore::remember(const Frame &frame, uint32_t now_ms) {
  seen_[seen_cursor_] = SeenFrame{true,
                                  frame.source,
                                  frame.destination,
                                  frame.type,
                                  frame.sequence,
                                  now_ms,
                                  dedup_source_session(frame),
                                  frame.destination_session,
                                  frame.root_session};
  seen_cursor_ = (seen_cursor_ + 1) % kDedupSlots;
}

void MeshCore::deliver_local(const Frame &frame, uint32_t now_ms) {
  ++counters_.delivered;
  if (callbacks_.deliver != nullptr)
    callbacks_.deliver(callbacks_.context, frame);
  if (frame.type == FrameType::PROBE) {
    Frame reply{};
    reply.type = FrameType::PROBE_REPLY;
    reply.destination = frame.source;
    reply.sequence = frame.sequence;
    reply.payload_length = frame.payload_length;
    for (size_t i = 0; i < frame.payload_length; ++i)
      reply.payload[i] = frame.payload[i];
    originate_owned_(reply, now_ms);
  }
}

void MeshCore::receive(NodeId immediate_sender, const Frame &frame, uint32_t now_ms) {
  receive(mesh_transport::ReceiveMetadata{interface_id_, immediate_sender, 0}, frame, now_ms);
}

void MeshCore::receive(const mesh_transport::ReceiveMetadata &metadata, const Frame &frame, uint32_t now_ms) {
  session_mode_locked_ = true;
  ++counters_.received;
  const NodeId immediate_sender = metadata.immediate_sender;
  if (metadata.interface_id != interface_id_ || !mesh_transport::validates_frame_budget(link_, frame.payload_length)) {
    ++counters_.invalid_drops;
    return;
  }
  if (!valid_id(node_id_) || !valid_id(immediate_sender) || immediate_sender == node_id_ || !frame_valid(frame) ||
      !sessions_match(frame) ||
      (frame.type != FrameType::BOOT_SESSION && session_resolver_ != nullptr && session(immediate_sender) == 0)) {
    ++counters_.invalid_drops;
    return;
  }
  if (frame.type == FrameType::BOOT_SESSION) {
    // The carrier has authenticated the configured forwarder. Bootstrap must
    // work before any neighbor/route/session exists, without learning one from
    // an unproved HELLO. Its dedup key includes the offered boot, not DATA's
    // replay window, so reused serials after reboot do not prevent admission.
    if (frame.source == node_id_ || seen_before(frame, now_ms)) {
      ++counters_.duplicate_drops;
      return;
    }
    remember(frame, now_ms);
    if ((frame.destination == 0 || frame.destination == node_id_) && callbacks_.deliver != nullptr)
      callbacks_.deliver(callbacks_.context, frame);
    if (frame.destination == node_id_)
      return;
    if (frame.ttl <= 1) {
      ++counters_.ttl_drops;
      return;
    }
    Frame forwarded = frame;
    --forwarded.ttl;
    if (emit(0, forwarded, now_ms))
      ++counters_.forwarded;
    return;
  }
  if (frame.type == FrameType::ADVERTISEMENT) {
    if (frame.source != immediate_sender) {
      ++counters_.invalid_drops;
      return;
    }
    auto &neighbor = neighbors_[immediate_sender];
    if (neighbor.seen && neighbor_current(immediate_sender, neighbor) &&
        !expired(now_ms, neighbor.last_seen, timing_.route_expiry_ms) &&
        !newer_sequence(frame.sequence, neighbor.sequence)) {
      ++counters_.duplicate_drops;
      return;
    }
    neighbor = Neighbor{true,       now_ms,          frame.sequence,       frame.root,
                        frame.rank, frame.path_bits, frame.source_session, frame.root_session};
    learned_[immediate_sender] =
        LearnedRoute{immediate_sender, now_ms, 0, 0, false, frame.source_session, frame.source_session};
    select_route(now_ms);
    return;
  }
  select_route(now_ms);
  if (frame.source == node_id_) {
    ++counters_.duplicate_drops;
    return;
  }
  const bool discovery = frame.type == FrameType::ROUTE_REQUEST || frame.type == FrameType::ROUTE_REPLY;
  // A shorter duplicate can improve the cache without being flooded again.
  if (discovery)
    learn_source(immediate_sender, frame, now_ms);
  if (seen_before(frame, now_ms)) {
    ++counters_.duplicate_drops;
    return;
  }
  if (frame.type == FrameType::ROUTE_REQUEST) {
    receive_route_request(immediate_sender, frame, now_ms);
    return;
  }
  if (frame.destination == node_id_) {
    remember(frame, now_ms);
    if (frame.type != FrameType::ROUTE_REPLY)
      deliver_local(frame, now_ms);
    return;
  }
  if (frame.ttl <= 1) {
    ++counters_.ttl_drops;
    return;
  }
  const NodeId hop = next_hop(frame.destination, immediate_sender, now_ms);
  if (hop == 0) {
    ++counters_.no_route_drops;
    if (frame.type != FrameType::ROUTE_REPLY)
      request_route(frame.destination, now_ms);
    return;
  }
  Frame forwarded = frame;
  --forwarded.ttl;
  if (emit(hop, forwarded, now_ms)) {
    // Rejected queue admission is not a transmission. Leave it retryable if
    // the previous hop offers this same frame again after backpressure clears.
    remember(frame, now_ms);
    ++counters_.forwarded;
  }
}

bool MeshCore::send_bootstrap(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                              uint32_t now_ms) {
  session_mode_locked_ = true;
  if (!bootstrap_allowed_ || payload == nullptr || length != mesh_session::WIRE_SIZE ||
      (destination != 0 && (!valid_id(destination) || destination == node_id_)))
    return false;
  Frame frame;
  frame.type = FrameType::BOOT_SESSION;
  frame.source = node_id_;
  frame.destination = destination;
  frame.sequence = sequence;
  frame.payload_length = static_cast<uint16_t>(length);
  for (size_t i = 0; i < length; ++i)
    frame.payload[i] = payload[i];
  if (!emit(0, frame, now_ms))
    return false;
  remember(frame, now_ms);
  return true;
}

bool MeshCore::originate(Frame frame, uint32_t now_ms) {
  return originate_owned_(frame, now_ms);
}

bool MeshCore::originate_owned_(Frame &frame, uint32_t now_ms) {
  session_mode_locked_ = true;
  frame.source = node_id_;
  frame.root = 0;
  frame.rank = 255;
  frame.path_bits = 0;
  if (frame.type == FrameType::ADVERTISEMENT || frame.type == FrameType::ROUTE_REQUEST ||
      frame.type == FrameType::ROUTE_REPLY || !bind_local(frame) || !frame_valid(frame) ||
      !mesh_transport::validates_frame_budget(link_, frame.payload_length)) {
    ++counters_.invalid_drops;
    return false;
  }
  select_route(now_ms);
  if (frame.destination == node_id_) {
    remember(frame, now_ms);
    deliver_local(frame, now_ms);
    return true;
  }
  const NodeId hop = next_hop(frame.destination, 0, now_ms);
  if (hop == 0) {
    ++counters_.no_route_drops;
    request_route(frame.destination, now_ms);
    return false;
  }
  if (!emit(hop, frame, now_ms))
    return false;
  remember(frame, now_ms);
  return true;
}

bool MeshCore::send_probe(NodeId destination, uint16_t sequence, uint32_t now_ms) {
  return send_probe_payload(destination, sequence, nullptr, 0, now_ms);
}

bool MeshCore::send_probe_payload(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                                  uint32_t now_ms) {
  return send_payload(FrameType::PROBE, destination, sequence, payload, length, now_ms);
}

bool MeshCore::send_control(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                            uint32_t now_ms) {
  return send_payload(FrameType::CONTROL, destination, sequence, payload, length, now_ms);
}

bool MeshCore::send_data(NodeId destination, uint16_t sequence, const uint8_t *payload, size_t length,
                         uint32_t now_ms) {
  return send_payload(FrameType::DATA, destination, sequence, payload, length, now_ms);
}

bool MeshCore::send_payload(FrameType type, NodeId destination, uint16_t sequence, const uint8_t *payload,
                            size_t length, uint32_t now_ms) {
  if (!mesh_transport::validates_frame_budget(link_, length) ||
      (type != FrameType::DATA && length > mesh_transport::kProtocolControlPayloadLimit) ||
      (length != 0 && payload == nullptr)) {
    ++counters_.invalid_drops;
    return false;
  }
  Frame frame{};
  frame.type = type;
  frame.destination = destination;
  frame.sequence = sequence;
  frame.payload_length = static_cast<uint16_t>(length);
  for (size_t i = 0; i < length; ++i)
    frame.payload[i] = payload[i];
  return originate_owned_(frame, now_ms);
}

}  // namespace mesh_core

namespace mesh_transport {

bool valid_transport(const Transport &transport, bool require_receive) {
  return valid_interface(transport.interface) && transport.enqueue != nullptr &&
         (!require_receive || transport.poll_receive != nullptr);
}

bool enqueue_checked(const Transport &transport, uint8_t next_hop, const mesh_core::Frame &frame, uint32_t now_ms) {
  if (!valid_transport(transport) || next_hop > mesh_core::kMaxNodes ||
      !validates_frame_budget(transport.interface.capabilities, frame.payload_length) ||
      !mesh_core::validate_frame(frame))
    return false;
  return transport.enqueue(transport.context, transport.interface.id, next_hop, frame, now_ms);
}

bool poll_receive_checked(const Transport &transport, ReceiveMetadata &metadata, mesh_core::Frame &frame) {
  metadata = ReceiveMetadata{};
  frame = mesh_core::Frame{};
  if (!valid_transport(transport, true))
    return false;
  ReceiveMetadata candidate{};
  mesh_core::Frame received{};
  if (!transport.poll_receive(transport.context, candidate, received))
    return false;
  if (candidate.interface_id != transport.interface.id || candidate.immediate_sender == 0 ||
      candidate.immediate_sender > mesh_core::kMaxNodes ||
      !validates_frame_budget(transport.interface.capabilities, received.payload_length) ||
      !mesh_core::validate_frame(received))
    return false;
  metadata = candidate;
  frame = received;
  return true;
}

}  // namespace mesh_transport
