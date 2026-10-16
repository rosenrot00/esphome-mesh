#include "mesh_espnow_transport.h"
#include "mesh_radio_frame.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include <algorithm>
#include <cstring>
#include <esp_wifi.h>

namespace esphome::mesh {
static const char *const TAG = "mesh_espnow";
static_assert(::mesh_core::kMaxWireSize <= EspNowTransport::NATIVE_FRAME_BUDGET,
              "Mesh frames must fit the selected native ESP-NOW v2 budget");
std::atomic<EspNowTransport *> EspNowTransport::instance_{nullptr};
namespace {
constexpr std::array<uint8_t, 6> BROADCAST_MAC{255, 255, 255, 255, 255, 255};
uint32_t mac_low(const uint8_t *mac) {
  return uint32_t(mac[0]) | uint32_t(mac[1]) << 8 | uint32_t(mac[2]) << 16 | uint32_t(mac[3]) << 24;
}
uint32_t mac_high(const uint8_t *mac) { return uint32_t(mac[4]) | uint32_t(mac[5]) << 8; }
// The associated AP's home channel is stable during a background scan.
// esp_wifi_get_channel() reports the temporary off-channel position instead.
bool home_channel(uint8_t &channel) {
  wifi_ap_record_t ap{};
  if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
    channel = ap.primary;
    return channel >= 1 && channel <= 14;
  }
  wifi_second_chan_t secondary;
  return esp_wifi_get_channel(&channel, &secondary) == ESP_OK && channel >= 1 && channel <= 14;
}
bool management_wire(const uint8_t *data, size_t length) {
  return length >= 3 && length <= EspNowTransport::MANAGEMENT_WIRE_SIZE && data[0] == 'M' && data[1] == 'A';
}
bool unicast_mac(const EspNowTransport::MacAddress &mac) {
  bool nonzero = false;
  for (const auto byte : mac)
    nonzero |= byte != 0;
  return nonzero && (mac[0] & 1) == 0;
}
const char *rate_name(EspNowTransport::PeerRate rate) {
  return rate == EspNowTransport::PeerRate::FAST   ? "FAST"
         : rate == EspNowTransport::PeerRate::BASE ? "BASE"
                                                   : "UNKNOWN";
}
const char *frame_class(uint8_t type) {
  return type == static_cast<uint8_t>(::mesh_core::FrameType::DATA)            ? "DATA"
         : type == static_cast<uint8_t>(::mesh_core::FrameType::ADVERTISEMENT) ? "ADV"
                                                                               : "CTRL";
}
}  // namespace

EspNowTransport::EspNowTransport() {
  static_assert(TX_CAPACITY <= 256, "TX slot IDs must fit uint8_t");
  for (size_t slot = 0; slot < TX_CAPACITY; ++slot)
    tx_order_[slot] = static_cast<uint8_t>(slot);
}

void EspNowTransport::set_wake_callback(void *context, ::mesh_transport::WakeCallback callback) {
  // Context is stable during SDK ownership. On clear, preserve it for a
  // callback that already captured the old pair before removal.
  portENTER_CRITICAL(&wake_lock_);
  wake_callback_ = callback;
  if (callback != nullptr) {
    wake_context_ = context;
  }
  portEXIT_CRITICAL(&wake_lock_);
}

void EspNowTransport::notify_worker_() const {
  portENTER_CRITICAL(&wake_lock_);
  const auto callback = wake_callback_;
  void *const context = wake_context_;
  portEXIT_CRITICAL(&wake_lock_);
  if (callback != nullptr)
    callback(context);
}

bool EspNowTransport::set_management_enabled(bool enabled) {
  if (espnow_ready_)
    return false;
  management_enabled_ = enabled;
  return true;
}

void EspNowTransport::publish_peer_(size_t index) {
  auto &lookup = peer_lookup_[index];
  lookup.generation.fetch_add(1);
  const bool active = index < peer_count_;
  lookup.low.store(active ? mac_low(peers_[index].mac.data()) : 0);
  lookup.high.store(active ? mac_high(peers_[index].mac.data()) : 0);
  lookup.node.store(active ? peers_[index].node_id : 0);
  lookup.generation.fetch_add(1);
}

::mesh_transport::ManagementTransport EspNowTransport::management_backend() {
  ::mesh_transport::ManagementTransport backend;
  backend.context = this;
  backend.wire_mtu = MANAGEMENT_WIRE_SIZE;
  backend.key_context = {"espnow-pmk", "espnow-session"};
  backend.ready = [](const void *context) { return static_cast<const EspNowTransport *>(context)->ready(); };
  backend.send = [](void *context, const ::mesh_transport::PeerAddress &destination, const uint8_t *data, size_t length,
                    uint32_t now) {
    return static_cast<EspNowTransport *>(context)->enqueue_management(destination, data, length, now);
  };
  backend.receive = [](void *context, ::mesh_transport::ManagementPacket &output) {
    ManagementPacket input;
    if (!static_cast<EspNowTransport *>(context)->poll_management(input))
      return false;
    output.source = input.source;
    output.length = input.length;
    if (input.length > sizeof(output.data))
      return false;
    std::memcpy(output.data, input.data, input.length);
    return true;
  };
  backend.configure_key = [](void *context, const ::mesh_transport::PeerLinkKey &key) {
    auto *self = static_cast<EspNowTransport *>(context);
    if (!self->set_management_enabled(true))
      return false;
    self->set_pmk(key);
    return true;
  };
  backend.install_peer = [](void *context, uint8_t node, const ::mesh_transport::PeerAddress &address,
                            const ::mesh_transport::PeerLinkKey &key) {
    return static_cast<EspNowTransport *>(context)->install_authenticated_peer(node, address, key);
  };
  backend.remove_peer = [](void *context, uint8_t node) {
    return static_cast<EspNowTransport *>(context)->remove_authenticated_peer(node);
  };
  backend.peer_address = [](const void *context, uint8_t node, ::mesh_transport::PeerAddress &address) {
    return static_cast<const EspNowTransport *>(context)->peer_address(node, address);
  };
  return backend;
}

uint8_t EspNowTransport::callback_node_(const uint8_t *mac, uint8_t *slot, uint32_t *generation) const {
  const uint32_t low = mac_low(mac), high = mac_high(mac);
  for (size_t index = 0; index < MAX_PEERS; ++index) {
    const auto &lookup = peer_lookup_[index];
    const uint32_t before = lookup.generation.load();
    if ((before & 1) != 0)
      continue;
    const uint32_t node = lookup.node.load();
    const bool equal = lookup.low.load() == low && lookup.high.load() == high;
    if (equal && node != 0 && lookup.generation.load() == before) {
      if (slot != nullptr)
        *slot = static_cast<uint8_t>(index);
      if (generation != nullptr)
        *generation = before;
      return static_cast<uint8_t>(node);
    }
  }
  return 0;
}

bool EspNowTransport::peer_address(uint8_t node, MacAddress &mac) const {
  for (size_t index = 0; index < peer_count_; index++) {
    if (peers_[index].node_id == node) {
      mac = peers_[index].mac;
      return true;
    }
  }
  return false;
}

bool EspNowTransport::peer_rate(uint8_t node, PeerRateStats &stats) const {
  for (size_t index = 0; index < peer_count_; index++) {
    if (peers_[index].node_id != node)
      continue;
    stats = PeerRateStats{espnow_ready_ ? tx_peer_rate_[index].configured() : PeerRate::UNKNOWN,
                          observed_base_success_[index], observed_fast_success_[index]};
    return true;
  }
  return false;
}

uint16_t EspNowTransport::configured_fast_mask() const {
  if (!espnow_ready_)
    return 0;
  uint16_t mask = 0;
  for (size_t index = 0; index < peer_count_; index++)
    if (tx_peer_rate_[index].configured() == PeerRate::FAST)
      mask |= static_cast<uint16_t>(1U << (peers_[index].node_id - 1));
  return mask;
}

void EspNowTransport::reset_peer_rate_(size_t peer, bool clear_observed) {
  tx_peer_rate_[peer].reset();
  if (clear_observed)
    observed_base_success_[peer] = observed_fast_success_[peer] = 0;
}

bool EspNowTransport::apply_peer_rate_(size_t peer, PeerRate rate) {
  esp_now_rate_config_t config{};
  config.phymode = rate == PeerRate::FAST ? WIFI_PHY_MODE_11G : WIFI_PHY_MODE_11B;
  config.rate = rate == PeerRate::FAST ? WIFI_PHY_RATE_6M : WIFI_PHY_RATE_1M_L;
  const auto err = esp_now_set_peer_rate_config(peers_[peer].mac.data(), &config);
  if (err == ESP_OK)
    return true;
  rate_errors_++;
  if (err == ESP_ERR_ESPNOW_NO_MEM)
    sdk_no_mem_("RATE", peers_[peer].node_id);
  return false;
}

bool EspNowTransport::prepare_peer_rate_(size_t peer, uint32_t now) {
  auto &policy = tx_peer_rate_[peer];
  const auto requested = policy.requested(now);
  if (requested == policy.configured())
    return true;
  if (!policy.configuration_due(now))
    return false;
  if (requested == PeerRate::FAST)
    rate_probes_++;
  if (apply_peer_rate_(peer, requested)) {
    policy.applied(requested, millis());
    return true;
  }
  // A failed setter has no documented rollback guarantee. Explicitly restore
  // the robust modulation, or isolate this peer until a bounded retry succeeds.
  policy.configuration_failed(requested, millis());
  if (tx_cooldown_active_)
    return false;
  if (requested == PeerRate::FAST) {
    if (apply_peer_rate_(peer, PeerRate::BASE)) {
      policy.applied(PeerRate::BASE, millis());
      return true;
    }
    policy.configuration_failed(PeerRate::BASE, millis());
  }
  return false;
}

void EspNowTransport::discard_peer_tx_(size_t peer, bool compact) {
  for (size_t offset = 0; offset < tx_count_;) {
    auto &packet = tx_packet_(offset);
    if (packet.peer_index == peer) {
      tx_drops_++;
      remove_tx_(offset);
      continue;
    }
    if (compact && packet.peer_index > peer)
      packet.peer_index--;
    ++offset;
  }
}

bool EspNowTransport::install_authenticated_peer(uint8_t node, const MacAddress &mac,
                                                 const std::array<uint8_t, 16> &lmk) {
  if (!management_enabled_ || tx_inflight_ || node < 1 || node > mesh_limits::MAX_NODES || !unicast_mac(mac) ||
      mac == own_mac_)
    return false;
  const int existing = peer_index_(mac.data());
  for (size_t index = 0; index < peer_count_; index++)
    if (peers_[index].node_id == node && static_cast<int>(index) != existing)
      return false;
  if (existing < 0 && peer_count_ >= MAX_PEERS)
    return false;
  const size_t index = existing < 0 ? peer_count_ : static_cast<size_t>(existing);
  if (existing >= 0 && peers_[index].node_id == node && peers_[index].lmk == lmk)
    return true;
  esp_now_peer_info_t peer{};
  std::memcpy(peer.peer_addr, mac.data(), 6);
  std::memcpy(peer.lmk, lmk.data(), 16);
  peer.ifidx = WIFI_IF_STA;
  peer.channel = 0;
  peer.encrypt = true;
  if (espnow_ready_ && (existing < 0 ? esp_now_add_peer(&peer) : esp_now_mod_peer(&peer)) != ESP_OK)
    return false;
  if (existing >= 0)
    discard_peer_tx_(index, false);
  else
    peer_count_++;
  peers_[index] = Peer{node, mac, lmk};
  tx_peer_failed_at_[index] = tx_peer_backoff_[index] = 0;
  tx_peer_data_burst_[index] = DATA_BURST_LIMIT;
  tx_peer_failure_streak_[index] = 0;
  reset_peer_rate_(index, true);
  if (espnow_ready_)
    prepare_peer_rate_(index, millis());
  publish_peer_(index);
  return true;
}

bool EspNowTransport::remove_authenticated_peer(uint8_t node) {
  if (!management_enabled_ || tx_inflight_)
    return false;
  size_t index = 0;
  while (index < peer_count_ && peers_[index].node_id != node)
    index++;
  if (index == peer_count_)
    return true;
  if (espnow_ready_ && esp_now_del_peer(peers_[index].mac.data()) != ESP_OK)
    return false;
  discard_peer_tx_(index, true);
  peer_count_--;
  for (size_t position = index; position < peer_count_; position++) {
    peers_[position] = peers_[position + 1];
    tx_peer_failed_at_[position] = tx_peer_failed_at_[position + 1];
    tx_peer_backoff_[position] = tx_peer_backoff_[position + 1];
    tx_peer_data_burst_[position] = tx_peer_data_burst_[position + 1];
    tx_peer_failure_streak_[position] = tx_peer_failure_streak_[position + 1];
    tx_peer_rate_[position] = tx_peer_rate_[position + 1];
    observed_base_success_[position] = observed_base_success_[position + 1];
    observed_fast_success_[position] = observed_fast_success_[position + 1];
    publish_peer_(position);
  }
  peers_[peer_count_] = Peer{};
  reset_peer_rate_(peer_count_, true);
  publish_peer_(peer_count_);
  tx_next_peer_ = peer_count_ == 0 ? 0 : tx_next_peer_ % peer_count_;
  return true;
}

bool EspNowTransport::enqueue_management(const MacAddress & /*destination*/, const uint8_t *data, size_t length,
                                         uint32_t now) {
  if (!sdk_enabled_ || !management_enabled_ || data == nullptr || !management_wire(data, length) ||
      management_tx_count_ >= MANAGEMENT_CAPACITY)
    return false;
  auto &packet = management_tx_[management_tx_tail_];
  packet.queued_at = now;
  packet.length = static_cast<uint16_t>(length);
  std::memcpy(packet.data, data, length);
  management_tx_tail_ = (management_tx_tail_ + 1) % MANAGEMENT_CAPACITY;
  management_tx_count_++;
  return true;
}

bool EspNowTransport::poll_management(ManagementPacket &packet) {
  return espnow_ready_ && management_rx_queue_ != nullptr && xQueueReceive(management_rx_queue_, &packet, 0) == pdTRUE;
}

bool EspNowTransport::add_peer(uint8_t node, const std::array<uint8_t, 6> &mac, const std::array<uint8_t, 16> &lmk) {
  if (espnow_ready_ || node < 1 || node > mesh_limits::MAX_NODES || peer_count_ >= MAX_PEERS)
    return false;
  for (size_t i = 0; i < peer_count_; i++)
    if (peers_[i].node_id == node || peers_[i].mac == mac)
      return false;
  peers_[peer_count_++] = Peer{node, mac, lmk};
  tx_peer_data_burst_[peer_count_ - 1] = DATA_BURST_LIMIT;
  reset_peer_rate_(peer_count_ - 1, true);
  publish_peer_(peer_count_ - 1);
  return true;
}

bool EspNowTransport::ensure_started(uint32_t now) {
  if (!sdk_enabled_) {
    service_disabled_(now);
    return false;
  }
  if (ready())
    return true;
  if (recovery_waiting_)
    return start_at_(now);
  if (now - last_init_attempt_ < 1000)
    return false;
  last_init_attempt_ = now;
  return start_at_(now);
}

void EspNowTransport::discard_receive() {
  if (rx_queue_ != nullptr)
    xQueueReset(rx_queue_);
  if (management_rx_queue_ != nullptr)
    xQueueReset(management_rx_queue_);
}

void EspNowTransport::cancel_pending(bool /*keep_inflight*/) {
  // Releasing a queue entry cannot cancel the SDK's pending result. Retain its
  // send/result association in either cancellation mode, but disable retry.
  if (tx_inflight_ && !management_inflight_) {
    tx_packet_().attempts = 4;
    tx_count_ = 1;
    tx_tail_ = (tx_head_ + 1) % TX_CAPACITY;
  } else {
    tx_head_ = tx_tail_ = tx_count_ = 0;
    if (!tx_inflight_)
      send_result_.store(-1, std::memory_order_release);
  }
  if (management_inflight_) {
    management_tx_count_ = 1;
    management_tx_tail_ = (management_tx_head_ + 1) % MANAGEMENT_CAPACITY;
  } else
    management_tx_head_ = management_tx_tail_ = management_tx_count_ = 0;
}

bool EspNowTransport::poll_receive(::mesh_transport::ReceiveMetadata &metadata, ::mesh_core::Frame &frame) {
  if (!ready() || rx_queue_ == nullptr)
    return false;
  uint8_t current_channel = 0;
  if (!home_channel(current_channel))
    current_channel = 0;
  RxPacket packet;
  for (size_t budget = 0; budget < RX_CAPACITY && xQueueReceive(rx_queue_, &packet, 0) == pdTRUE; budget++) {
    uint8_t binding_slot = 0;
    uint32_t binding_generation = 0;
    if (callback_node_(packet.source.data(), &binding_slot, &binding_generation) != packet.sender ||
        binding_slot != packet.binding_slot || binding_generation != packet.binding_generation ||
        (packet.channel != 0 && packet.channel != current_channel) ||
        !::mesh_radio::decode_radio_frame(packet.data, packet.length, current_channel, frame) ||
        (frame.type == ::mesh_core::FrameType::ADVERTISEMENT && frame.source != packet.sender)) {
      rx_drops_.fetch_add(1);
      continue;
    }
    received_++;
    metadata.interface_id = interface_id_;
    metadata.immediate_sender = packet.sender;
    metadata.channel = packet.channel;
    return true;
  }
  return false;
}

::mesh_transport::Transport EspNowTransport::transport(::mesh_transport::InterfaceId id) {
  if (id == ::mesh_transport::kNoInterface || (descriptor_exported_ && id != interface_id_)) {
    ::mesh_transport::Transport invalid;
    invalid.interface.id = ::mesh_transport::kNoInterface;
    return invalid;
  }
  interface_id_ = id;
  descriptor_exported_ = true;
  ::mesh_transport::Transport backend;
  backend.context = this;
  backend.interface.id = id;
  auto &link = backend.interface.capabilities;
  link.payload_mtu =
      ::mesh_transport::payload_mtu_for_frame_budget(NATIVE_FRAME_BUDGET, 0, ::mesh_core::kSessionWireHeaderSize);
  link.security_provided = true;
  link.channel_selection_supported = true;
  link.first_channel = 1;
  link.last_channel = 14;
  backend.enqueue = [](void *context, ::mesh_transport::InterfaceId interface, uint8_t hop,
                       const ::mesh_core::Frame &frame, uint32_t now) {
    auto *self = static_cast<EspNowTransport *>(context);
    return interface == self->interface_id_ && self->enqueue(hop, frame, now);
  };
  backend.poll_receive = [](void *context, ::mesh_transport::ReceiveMetadata &metadata, ::mesh_core::Frame &frame) {
    return static_cast<EspNowTransport *>(context)->poll_receive(metadata, frame);
  };
  backend.process = [](void *context, uint32_t now, bool allow_start) {
    auto *self = static_cast<EspNowTransport *>(context);
    self->ensure_started(now);
    self->process(now, allow_start);
  };
  backend.set_wake_callback = [](void *context, void *wake_context, ::mesh_transport::WakeCallback callback) {
    static_cast<EspNowTransport *>(context)->set_wake_callback(wake_context, callback);
  };
  backend.start = [](void *context) { return static_cast<EspNowTransport *>(context)->start(); };
  backend.stop = [](void *context) { static_cast<EspNowTransport *>(context)->stop(); };
  backend.cancel_pending = [](void *context, bool keep_inflight) {
    static_cast<EspNowTransport *>(context)->cancel_pending(keep_inflight);
  };
  backend.discard_receive = [](void *context) { static_cast<EspNowTransport *>(context)->discard_receive(); };
  backend.queue_state = [](const void *context) {
    const auto *self = static_cast<const EspNowTransport *>(context);
    return ::mesh_transport::QueueState{self->pending_count(), self->capacity(), self->busy()};
  };
  backend.counters = [](const void *context) {
    const auto *self = static_cast<const EspNowTransport *>(context);
    return ::mesh_transport::TransportCounters{self->accepted_,       self->rejected_, self->sent_,
                                               self->failure_count(), self->received_, self->rx_drop_count(),
                                               self->tx_drop_count()};
  };
  return backend;
}

int EspNowTransport::peer_index_(const uint8_t *mac) const {
  for (size_t i = 0; i < this->peer_count_; i++)
    if (std::memcmp(this->peers_[i].mac.data(), mac, 6) == 0)
      return static_cast<int>(i);
  return -1;
}

bool EspNowTransport::start() { return start_at_(millis()); }

bool EspNowTransport::start_at_(uint32_t now) {
  if (!sdk_enabled_) {
    service_disabled_(now);
    return false;
  }
  if (this->espnow_ready_)
    return true;
  const auto *owner = instance_.load(std::memory_order_acquire);
  if (owner != nullptr && owner != this)
    return false;
  if (recovery_waiting_) {
    const uint32_t age = now - recovery_at_;
    if (age >= 0x80000000U || age < recovery_backoff_)
      return false;
    recovery_waiting_ = false;
  }
  // Failed deinitialization does not establish quiescence. Retain ownership
  // and the pending send/result association until teardown actually succeeds.
  if (sdk_initialized_) {
    if (!teardown_sdk_()) {
      schedule_recovery_();
      return false;
    }
    finish_teardown_();
  }
  if (this->rx_queue_ == nullptr)
    this->rx_queue_ =
        xQueueCreateStatic(RX_CAPACITY, sizeof(RxPacket), this->rx_queue_buffer_, &this->rx_queue_storage_);
  if (this->rx_queue_ == nullptr)
    return false;
  if (management_enabled_ && management_rx_queue_ == nullptr)
    management_rx_queue_ = xQueueCreateStatic(MANAGEMENT_CAPACITY, sizeof(ManagementPacket), management_rx_buffer_,
                                              &management_rx_storage_);
  if (management_enabled_ && management_rx_queue_ == nullptr)
    return false;
  discard_receive();
  const esp_err_t mac_err = esp_wifi_get_mac(WIFI_IF_STA, this->own_mac_.data());
  if (mac_err != ESP_OK) {
    ESP_LOGW(TAG, "Wi-Fi driver is not ready: %s", esp_err_to_name(mac_err));
    return false;
  }
  esp_err_t err = espnow_driver::acquire(this->sdk_consumer_);
  this->sdk_initialized_ = espnow_driver::owns(this->sdk_consumer_);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "ESP-NOW init failed: %s", esp_err_to_name(err));
    if (err == ESP_ERR_ESPNOW_NO_MEM)
      sdk_no_mem_("INIT");
    schedule_recovery_();
    return false;
  }
  sdk_initialized_ = true;
  const char *failure_origin = "INIT";
  instance_.store(this, std::memory_order_release);
  // Every SDK restart restores our receive contract. Keeping the default
  // connectionless interval and the maximum RX window permits arbitrary
  // asynchronous relay traffic while preserving ESPHome's Wi-Fi PS setting.
  static_assert(RECEIVE_INTERVAL_MS == ESP_WIFI_CONNECTIONLESS_INTERVAL_DEFAULT_MODE,
                "Continuous receive uses the SDK default interval");
  err = esp_now_set_wake_window(RECEIVE_WINDOW_MS);
  if (err == ESP_OK)
    err = esp_wifi_connectionless_module_set_wake_interval(RECEIVE_INTERVAL_MS);
  if (err == ESP_OK)
    err = esp_now_set_pmk(this->pmk_.data());
  if (err == ESP_OK && management_enabled_) {
    esp_now_peer_info_t peer{};
    std::memcpy(peer.peer_addr, BROADCAST_MAC.data(), 6);
    peer.ifidx = WIFI_IF_STA;
    peer.channel = 0;
    peer.encrypt = false;
    err = esp_now_add_peer(&peer);
    if (err == ESP_OK) {
      esp_now_rate_config_t config{};
      config.phymode = WIFI_PHY_MODE_11B;
      config.rate = WIFI_PHY_RATE_1M_L;
      failure_origin = "RATE";
      err = esp_now_set_peer_rate_config(BROADCAST_MAC.data(), &config);
      if (err != ESP_OK)
        rate_errors_++;
      else
        failure_origin = "INIT";
    }
  }
  for (size_t i = 0; err == ESP_OK && i < this->peer_count_; i++) {
    esp_now_peer_info_t peer{};
    std::memcpy(peer.peer_addr, this->peers_[i].mac.data(), 6);
    std::memcpy(peer.lmk, this->peers_[i].lmk.data(), 16);
    peer.ifidx = WIFI_IF_STA;
    peer.channel = 0;  // Follow the current PHY, including mesh channel acquisition.
    peer.encrypt = true;
    err = esp_now_add_peer(&peer);
    reset_peer_rate_(i, false);
    if (err == ESP_OK && !tx_cooldown_active_)
      prepare_peer_rate_(i, millis());
    publish_peer_(i);
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "ESP-NOW setup failed: %s", esp_err_to_name(err));
    if (err == ESP_ERR_ESPNOW_NO_MEM)
      sdk_no_mem_(failure_origin);
    if (teardown_sdk_())
      finish_teardown_();
    schedule_recovery_();
    return false;
  }
  this->espnow_ready_ = true;
  callbacks_enabled_.store(true, std::memory_order_release);
  const auto &mac = this->own_mac_;
  ESP_LOGI(TAG, "Node %u STA MAC %02X:%02X:%02X:%02X:%02X:%02X, %u encrypted peers", this->node_id_, mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5], static_cast<unsigned>(this->peer_count_));
  return true;
}

bool EspNowTransport::teardown_sdk_() {
  this->espnow_ready_ = false;
  callbacks_enabled_.store(false, std::memory_order_release);
  this->send_result_.store(-1, std::memory_order_release);
  if (sdk_initialized_) {
    const auto err = espnow_driver::release(this->sdk_consumer_);
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "ESP-NOW teardown failed; retain SDK ownership: %s", esp_err_to_name(err));
      return false;
    }
    sdk_initialized_ = false;
  }
  if (instance_.load(std::memory_order_acquire) == this)
    instance_.store(nullptr, std::memory_order_release);
  return true;
}

void EspNowTransport::clear_pending_() {
  this->tx_inflight_ = false;
  this->management_inflight_ = false;
  this->send_result_.store(-1);
  this->tx_head_ = this->tx_tail_ = this->tx_count_ = 0;
  this->management_tx_head_ = this->management_tx_tail_ = this->management_tx_count_ = 0;
  discard_receive();
}

void EspNowTransport::finish_teardown_() {
  if (stop_requested_) {
    clear_pending_();
    stop_requested_ = false;
    recovery_waiting_ = tx_cooldown_active_ = false;
    recovery_backoff_ = 0;
  } else if (recovery_packet_pending_) {
    // Only the packet with an uncertain SDK outcome is discarded. Other
    // bounded queues keep their normal freshness/expiry policy.
    if (management_inflight_) {
      management_tx_head_ = (management_tx_head_ + 1) % MANAGEMENT_CAPACITY;
      management_tx_count_--;
    } else {
      tx_head_ = (tx_head_ + 1) % TX_CAPACITY;
      tx_count_--;
    }
    tx_drops_++;
    tx_inflight_ = management_inflight_ = false;
    discard_receive();
  }
  recovery_packet_pending_ = false;
}

void EspNowTransport::schedule_recovery_() {
  const uint32_t now = millis();
  recovery_backoff_ = recovery_backoff_ == 0                     ? RECOVERY_MIN_MS
                      : recovery_backoff_ >= RECOVERY_MAX_MS / 2 ? RECOVERY_MAX_MS
                                                                 : recovery_backoff_ * 2;
  recovery_at_ = now;
  recovery_waiting_ = true;
  last_init_attempt_ = now;
}

void EspNowTransport::sdk_no_mem_(const char *origin, uint8_t peer) {
  const uint32_t now = millis();
  tx_cooldown_at_ = now;
  tx_cooldown_active_ = true;
  sdk_no_mem_count_++;
  tx_failures_++;
  if (sdk_no_mem_count_ == 1 || now - last_no_mem_log_ >= 1000) {
    last_no_mem_log_ = now;
    ESP_LOGW(TAG, "ESP-NOW SDK memory pressure: count=%u; pause all submissions for %u ms origin=%s peer=%u",
             static_cast<unsigned>(sdk_no_mem_count_), SDK_NO_MEM_COOLDOWN_MS, origin, peer);
  }
}

bool EspNowTransport::peer_failed_(size_t peer, uint8_t attempts, uint32_t now) {
  tx_peer_failed_at_[peer] = now;
  const bool exhausted = attempts >= 4 || tx_peer_failure_streak_[peer] != 0;
  if (exhausted) {
    // Fast retries repair transient loss. Only an exhausted packet opens the
    // dead-neighbour circuit, protecting other peers from repeated slow MAC
    // failures in the radio's single callback slot. An open circuit permits
    // one half-open probe after its delay; only real success closes it.
    auto &streak = tx_peer_failure_streak_[peer];
    if (streak < 3)
      streak++;
    tx_peer_backoff_[peer] = static_cast<uint16_t>(250U << (streak - 1));
  } else {
    tx_peer_backoff_[peer] =
        std::min<uint16_t>(LINK_RETRY_MAX_MS, static_cast<uint16_t>(LINK_RETRY_MIN_MS << (attempts - 1)));
  }
  return exhausted;
}

void EspNowTransport::stop() {
  stop_requested_ = true;
  if (!teardown_sdk_()) {
    schedule_recovery_();
    return;
  }
  finish_teardown_();
  recovery_waiting_ = tx_cooldown_active_ = false;
  recovery_backoff_ = 0;
}

bool EspNowTransport::set_sdk_enabled(bool enabled) {
  if (sdk_enabled_ != enabled) {
    sdk_enabled_ = enabled;
    if (!enabled) {
      stop_requested_ = true;
      espnow_ready_ = false;
      callbacks_enabled_.store(false, std::memory_order_release);
      send_result_.store(-1, std::memory_order_release);
    }
  }
  return enabled || service_disabled_(millis());
}

bool EspNowTransport::service_disabled_(uint32_t now) {
  if (!sdk_initialized_) {
    if (stop_requested_)
      finish_teardown_();
    return sdk_quiescent();
  }
  if (recovery_waiting_) {
    const uint32_t age = now - recovery_at_;
    if (age >= 0x80000000U || age < recovery_backoff_)
      return false;
  }
  if (!teardown_sdk_()) {
    schedule_recovery_();
    return false;
  }
  finish_teardown_();
  return sdk_quiescent();
}

void EspNowTransport::receive_callback_(const esp_now_recv_info_t *info, const uint8_t *data, int length) {
  auto *self = instance_.load(std::memory_order_acquire);
  if (self == nullptr || !self->callbacks_enabled_.load(std::memory_order_acquire) || info == nullptr ||
      info->src_addr == nullptr || data == nullptr || self->rx_queue_ == nullptr)
    return;
  if (length > 0 && self->management_enabled_ && management_wire(data, static_cast<size_t>(length))) {
    if (info->des_addr == nullptr || self->management_rx_queue_ == nullptr ||
        (std::memcmp(info->des_addr, self->own_mac_.data(), 6) != 0 &&
         std::memcmp(info->des_addr, BROADCAST_MAC.data(), 6) != 0)) {
      self->rx_drops_.fetch_add(1);
      return;
    }
    ManagementPacket packet{};
    std::memcpy(packet.source.data(), info->src_addr, 6);
    packet.channel = info->rx_ctrl == nullptr ? 0 : info->rx_ctrl->channel;
    packet.length = static_cast<uint16_t>(length);
    std::memcpy(packet.data, data, length);
    if (xQueueSend(self->management_rx_queue_, &packet, 0) != pdTRUE)
      self->rx_drops_.fetch_add(1);
    else
      self->notify_worker_();
    return;
  }
  uint8_t binding_slot = 0;
  uint32_t binding_generation = 0;
  const uint8_t sender = self->callback_node_(info->src_addr, &binding_slot, &binding_generation);
  // Encrypted ESP-NOW unicast is required. Never accept plaintext broadcast.
  if (sender == 0 || info->des_addr == nullptr || std::memcmp(info->des_addr, self->own_mac_.data(), 6) != 0 ||
      length < static_cast<int>(::mesh_core::kWireHeaderSize) || length > static_cast<int>(::mesh_core::kMaxWireSize)) {
    self->rx_drops_.fetch_add(1);
    return;
  }
  if (self->rx_callback_busy_.exchange(true, std::memory_order_acquire)) {
    self->rx_drops_.fetch_add(1);
    return;
  }
  RxPacket &packet = self->rx_callback_packet_;
  std::memcpy(packet.source.data(), info->src_addr, 6);
  packet.binding_slot = binding_slot;
  packet.binding_generation = binding_generation;
  packet.sender = sender;
  packet.channel = info->rx_ctrl == nullptr ? 0 : info->rx_ctrl->channel;
  packet.length = static_cast<uint16_t>(length);
  std::memcpy(packet.data, data, length);
  const bool published = xQueueSend(self->rx_queue_, &packet, 0) == pdTRUE;
  if (!published)
    self->rx_drops_.fetch_add(1);
  self->rx_callback_busy_.store(false, std::memory_order_release);
  if (published)
    self->notify_worker_();
  // No parsing, logging, allocation, or core calls in the high priority Wi-Fi task.
}

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
void EspNowTransport::send_callback_(const esp_now_send_info_t *info, esp_now_send_status_t status) {
  const uint8_t *mac = info == nullptr ? nullptr : info->des_addr;
  const int observed_rate = info == nullptr                    ? 0
                            : info->rate == WIFI_PHY_RATE_1M_L ? 1
                            : info->rate == WIFI_PHY_RATE_6M   ? 2
                                                               : 3;
#else
void EspNowTransport::send_callback_(const uint8_t *mac, esp_now_send_status_t status) {
  constexpr int observed_rate = 0;
#endif
  auto *self = instance_.load(std::memory_order_acquire);
  if (self == nullptr || !self->callbacks_enabled_.load(std::memory_order_acquire) || mac == nullptr)
    return;
  // One atomic mailbox holds the expected peer or its completed result. A late
  // callback for another peer, an idle transport, or a duplicate cannot finish
  // the current send. The SDK exposes no per-send token on older IDF versions;
  // this is deliberately not an epoch guarantee for callbacks to the same MAC.
  int pending = self->send_result_.load(std::memory_order_acquire);
  if (pending > -2 || self->send_destination_low_.load(std::memory_order_relaxed) != mac_low(mac) ||
      self->send_destination_high_.load(std::memory_order_relaxed) != mac_high(mac))
    return;
  const int completed = (status == ESP_NOW_SEND_SUCCESS ? 1 : 0) | (observed_rate << 1);
  if (self->send_result_.compare_exchange_strong(pending, completed, std::memory_order_release,
                                                std::memory_order_relaxed))
    self->notify_worker_();
}

void EspNowTransport::set_send_destination_(const uint8_t *mac) {
  send_destination_low_.store(mac_low(mac), std::memory_order_relaxed);
  send_destination_high_.store(mac_high(mac), std::memory_order_relaxed);
}

bool EspNowTransport::send_management_(uint32_t now) {
  while (management_tx_count_ != 0) {
    auto &packet = management_tx_[management_tx_head_];
    const uint32_t age = now - packet.queued_at;
    if (age < 1000 || age >= 0x80000000U)
      break;
    management_tx_head_ = (management_tx_head_ + 1) % MANAGEMENT_CAPACITY;
    management_tx_count_--;
    queue_expiries_++;
    tx_drops_++;
  }
  if (management_tx_count_ == 0)
    return false;
  auto &packet = management_tx_[management_tx_head_];
  set_send_destination_(BROADCAST_MAC.data());
  send_result_.store(-2 - static_cast<int>(MAX_PEERS), std::memory_order_release);
  tx_inflight_ = management_inflight_ = last_send_management_ = true;
  tx_started_ = millis();
  const auto err = esp_now_send(BROADCAST_MAC.data(), packet.data, packet.length);
  if (err != ESP_OK) {
    tx_inflight_ = management_inflight_ = false;
    send_result_.store(-1, std::memory_order_release);
    if (err == ESP_ERR_ESPNOW_NO_MEM) {
      sdk_no_mem_("MGMT");
    } else {
      tx_failures_++;
      management_tx_head_ = (management_tx_head_ + 1) % MANAGEMENT_CAPACITY;
      management_tx_count_--;
    }
  }
  return true;
}

bool EspNowTransport::enqueue(uint8_t next_hop, const ::mesh_core::Frame &frame, uint32_t now) {
  if (!sdk_enabled_) {
    this->rejected_++;
    return false;
  }
  uint8_t encoded[::mesh_core::kMaxWireSize];
  size_t length = 0;
  uint8_t channel = 0;
  if (frame.type == ::mesh_core::FrameType::ADVERTISEMENT && !home_channel(channel)) {
    this->tx_drops_++;
    this->rejected_++;
    return false;
  }
  if (!::mesh_radio::encode_radio_frame(frame, channel, encoded, sizeof(encoded), length)) {
    this->tx_drops_++;
    this->rejected_++;
    return false;
  }
  this->prune_tx_(now);
  size_t required = 0;
  size_t targets = 0;
  size_t replacements[MAX_PEERS];
  const size_t peer_capacity = this->peer_count_ == 0 ? 0 : TX_CAPACITY / this->peer_count_;
  const bool advertisement = frame.type == ::mesh_core::FrameType::ADVERTISEMENT;
  const bool data = frame.type == ::mesh_core::FrameType::DATA;
  // Keep one advertisement and at least one ordinary control slot per peer.
  // This is a short link backlog, not an IP-flow scheduler. Endpoints retain
  // complete datagrams and decide which flow supplies the next DATA fragment.
  const size_t data_capacity = std::min(CLASS_CAPACITY_PER_PEER, peer_capacity > 2 ? peer_capacity - 2 : 0);
  const size_t control_capacity =
      std::min(CLASS_CAPACITY_PER_PEER, peer_capacity > data_capacity + 1 ? peer_capacity - data_capacity - 1 : 0);
  for (size_t i = 0; i < this->peer_count_; i++) {
    replacements[i] = TX_CAPACITY;
    if (next_hop != 0 && this->peers_[i].node_id != next_hop)
      continue;
    targets++;
    size_t queued = 0;
    size_t queued_data = 0;
    size_t queued_control = 0;
    for (size_t offset = 0; offset < this->tx_count_; offset++) {
      const size_t index = this->tx_order_[(this->tx_head_ + offset) % TX_CAPACITY];
      const auto &packet = this->tx_queue_[index];
      if (packet.peer_index != i)
        continue;
      queued++;
      if (packet.data[3] == static_cast<uint8_t>(::mesh_core::FrameType::DATA))
        queued_data++;
      else if (packet.data[3] != static_cast<uint8_t>(::mesh_core::FrameType::ADVERTISEMENT))
        queued_control++;
      if (advertisement && !(this->tx_inflight_ && !this->management_inflight_ && offset == 0) &&
          packet.data[3] == static_cast<uint8_t>(::mesh_core::FrameType::ADVERTISEMENT))
        replacements[i] = index;
    }
    if (replacements[i] != TX_CAPACITY)
      continue;
    // Every provisioned peer retains its fair share and one advertisement slot.
    // A failed/unreachable neighbour cannot consume the live peer's capacity.
    if (queued >= peer_capacity ||
        (!advertisement && (data ? queued_data >= data_capacity : queued_control >= control_capacity))) {
      this->tx_drops_++;
      this->rejected_++;
      return false;
    }
    required++;
  }
  // A logical send is accepted atomically; the fragmenter must retain data
  // when the radio queue cannot accept it. Fanout cannot partially consume it.
  if (targets == 0 || required > TX_CAPACITY - this->tx_count_) {
    this->tx_drops_++;
    this->rejected_++;
    return false;
  }
  for (size_t i = 0; i < this->peer_count_; i++) {
    if (next_hop != 0 && this->peers_[i].node_id != next_hop)
      continue;
    const bool replace = replacements[i] != TX_CAPACITY;
    auto &packet = this->tx_queue_[replace ? replacements[i] : this->tx_order_[this->tx_tail_]];
    packet.peer_index = i;
    packet.attempts = 0;
    packet.length = length;
    packet.queued_at = now;
    std::memcpy(packet.data, encoded, length);
    if (!replace) {
      this->tx_tail_ = (this->tx_tail_ + 1) % TX_CAPACITY;
      this->tx_count_++;
    }
  }
  this->accepted_++;
  return true;
}

void EspNowTransport::prune_tx_(uint32_t now) {
  for (size_t offset = 0; offset < this->tx_count_;) {
    const auto &packet = this->tx_packet_(offset);
    const uint32_t age = now - packet.queued_at;
    // The worker may have captured `now` just before an RX callback enqueued a
    // packet with a newer millis(). That small future timestamp is not expiry.
    if (!(this->tx_inflight_ && !this->management_inflight_ && offset == 0) && age >= 1000 && age < 0x80000000U) {
      this->tx_drops_++;
      this->queue_expiries_++;
      this->remove_tx_(offset);
      continue;
    }
    ++offset;
  }
}

void EspNowTransport::remove_tx_(size_t offset) {
  const uint8_t freed = this->tx_order_[(this->tx_head_ + offset) % TX_CAPACITY];
  for (size_t next = offset + 1; next < this->tx_count_; ++next)
    this->tx_order_[(this->tx_head_ + next - 1) % TX_CAPACITY] =
        this->tx_order_[(this->tx_head_ + next) % TX_CAPACITY];
  --this->tx_count_;
  this->tx_tail_ = (this->tx_head_ + this->tx_count_) % TX_CAPACITY;
  this->tx_order_[this->tx_tail_] = freed;
}

void EspNowTransport::process(uint32_t now, bool allow_start) {
  if (!sdk_enabled_) {
    service_disabled_(now);
    return;
  }
  if (!this->espnow_ready_)
    return;
  if (this->tx_inflight_) {
    const int result = this->send_result_.load(std::memory_order_acquire);
    if (result < 0) {
      const uint32_t age = now - this->tx_started_;
      if (age < 0x80000000U && age >= SEND_CALLBACK_TIMEOUT_MS) {
        // Capture the outstanding send before teardown can release its entry.
        // Only compact identities and enums are logged, never keys or MACs.
        const auto &packet = tx_packet_();
        const uint8_t peer = management_inflight_ ? 0 : peers_[packet.peer_index].node_id;
        const char *kind = management_inflight_ ? "MGMT" : frame_class(packet.data[3]);
        const unsigned length = management_inflight_ ? management_tx_[management_tx_head_].length : packet.length;
        const unsigned attempts = management_inflight_ ? 1 : packet.attempts;
        const char *rate = management_inflight_ ? "BASE" : rate_name(tx_peer_rate_[packet.peer_index].configured());
        ESP_LOGW(
            TAG,
            "ESP-NOW send callback timeout: age=%u ms; reset transport peer=%u class=%s len=%u attempts=%u rate=%s",
            static_cast<unsigned>(age), peer, kind, length, attempts, rate);
        this->tx_failures_++;
        // The SDK gives no per-send token. Tear down before another send can
        // reuse the mailbox, and avoid a rapid deinit/init loop under load.
        recovery_packet_pending_ = true;
        if (teardown_sdk_())
          finish_teardown_();
        schedule_recovery_();
      }
      return;
    }
    this->send_result_.store(-1, std::memory_order_release);
    this->tx_inflight_ = false;
    const bool succeeded = (result & 1) != 0;
    if (succeeded) {
      recovery_backoff_ = 0;
      tx_cooldown_active_ = false;
    }
    if (management_inflight_) {
      management_inflight_ = false;
      if (!succeeded) {
        tx_failures_++;
        tx_drops_++;
      }
      management_tx_head_ = (management_tx_head_ + 1) % MANAGEMENT_CAPACITY;
      management_tx_count_--;
    } else {
      const size_t peer = this->tx_packet_().peer_index;
      bool exhausted = false;
      if (!succeeded) {
        this->tx_failures_++;
        if (tx_peer_rate_[peer].failed(millis()))
          rate_fallbacks_++;
        exhausted = peer_failed_(peer, this->tx_packet_().attempts, millis());
      } else {
        tx_peer_rate_[peer].succeeded(millis());
        if ((result >> 1) == 1)
          observed_base_success_[peer]++;
        else if ((result >> 1) == 2)
          observed_fast_success_[peer]++;
        this->tx_peer_backoff_[peer] = 0;
        this->tx_peer_failure_streak_[peer] = 0;
        this->sent_++;
      }
      if (succeeded || exhausted) {
        if (!succeeded) {
          this->tx_drops_++;
          this->retry_exhausted_++;
        }
        this->tx_head_ = (this->tx_head_ + 1) % TX_CAPACITY;
        this->tx_count_--;
      }
    }
  }
  // A channel hop consumes the outstanding callback (including failures and
  // timeout recovery), then suppresses retries/new packets until the PHY moves.
  this->prune_tx_(now);
  if (!allow_start)
    return;
  if (tx_cooldown_active_) {
    const uint32_t age = now - tx_cooldown_at_;
    if (age >= 0x80000000U || age < SDK_NO_MEM_COOLDOWN_MS)
      return;
    tx_cooldown_active_ = false;
  }
  size_t selected = TX_CAPACITY;
  for (size_t offset = 0; offset < this->peer_count_ && selected == TX_CAPACITY; offset++) {
    const size_t peer = (this->tx_next_peer_ + offset) % this->peer_count_;
    if (this->tx_peer_backoff_[peer] != 0) {
      const uint32_t age = now - this->tx_peer_failed_at_[peer];
      if (age >= 0x80000000U || age < this->tx_peer_backoff_[peer])
        continue;
    }
    size_t first_data = TX_CAPACITY, first_control = TX_CAPACITY;
    for (size_t packet = 0; packet < this->tx_count_; packet++) {
      if (this->tx_packet_(packet).peer_index == peer) {
        const auto type = this->tx_packet_(packet).data[3];
        if (type == static_cast<uint8_t>(::mesh_core::FrameType::DATA)) {
          if (first_data == TX_CAPACITY)
            first_data = packet;
        } else if (first_control == TX_CAPACITY)
          first_control = packet;
      }
    }
    if (first_data == TX_CAPACITY && first_control == TX_CAPACITY)
      continue;
    const bool rate_ready = prepare_peer_rate_(peer, now);
    if (tx_cooldown_active_)
      return;
    if (!rate_ready)
      continue;
    if (first_control != TX_CAPACITY && (first_data == TX_CAPACITY || tx_peer_data_burst_[peer] >= DATA_BURST_LIMIT))
      selected = first_control;
    else
      selected = first_data;
  }
  // Alternate a management carrier send with a normal mesh send whenever
  // both are eligible. Discovery cannot monopolize the SDK's one send slot.
  if (management_tx_count_ != 0 && (!last_send_management_ || selected == TX_CAPACITY)) {
    if (send_management_(now))
      return;
  }
  if (selected == TX_CAPACITY)
    return;
  // Preserve FIFO within each peer/class, with bounded service for both
  // classes. Retry attempts consume the same share as first attempts, so a
  // failing control frame cannot monopolize an otherwise usable DATA link.
  // Extract its slot ID stably. Rotating the skipped prefix to the tail
  // would reorder a class that has entries on both sides of the selection.
  const auto chosen = this->tx_order_[(this->tx_head_ + selected) % TX_CAPACITY];
  for (size_t offset = selected; offset != 0; offset--)
    this->tx_order_[(this->tx_head_ + offset) % TX_CAPACITY] =
        this->tx_order_[(this->tx_head_ + offset - 1) % TX_CAPACITY];
  this->tx_order_[this->tx_head_] = chosen;
  auto &packet = this->tx_packet_();
  this->tx_next_peer_ = (packet.peer_index + 1) % this->peer_count_;
  const size_t header_size = ::mesh_core::wire_header_size_for_version(packet.data[2]);
  if (header_size != 0 && packet.length == header_size + ::mesh_radio::ADVERTISEMENT_RADIO_TRAILER_SIZE &&
      packet.data[3] == static_cast<uint8_t>(::mesh_core::FrameType::ADVERTISEMENT)) {
    uint8_t current = 0;
    // Native STA may have roamed since enqueue. Re-read its AP home channel
    // on each submission; a temporary background-scan channel is not a route.
    if (!home_channel(current)) {
      this->tx_head_ = (this->tx_head_ + 1) % TX_CAPACITY;
      this->tx_count_--;
      this->tx_drops_++;
      return;
    }
    packet.data[header_size + 3] = current;
  }
  packet.attempts++;
  if (packet.data[3] == static_cast<uint8_t>(::mesh_core::FrameType::DATA)) {
    auto &burst = tx_peer_data_burst_[packet.peer_index];
    if (burst < DATA_BURST_LIMIT)
      burst++;
  } else
    tx_peer_data_burst_[packet.peer_index] = 0;
  set_send_destination_(this->peers_[packet.peer_index].mac.data());
  this->send_result_.store(-2 - static_cast<int>(packet.peer_index), std::memory_order_release);
  this->tx_inflight_ = true;
  this->management_inflight_ = this->last_send_management_ = false;
  this->tx_started_ = millis();
  const esp_err_t err = esp_now_send(this->peers_[packet.peer_index].mac.data(), packet.data, packet.length);
  if (err != ESP_OK) {
    this->tx_inflight_ = false;
    this->send_result_.store(-1, std::memory_order_release);
    if (err == ESP_ERR_ESPNOW_NO_MEM) {
      // The SDK rejected admission, so no over-air retry was consumed. Back
      // off the entire radio; rotating peers cannot relieve shared pressure.
      packet.attempts--;
      sdk_no_mem_("SEND", peers_[packet.peer_index].node_id);
      return;
    }
    this->tx_failures_++;
    const size_t peer = packet.peer_index;
    if (peer_failed_(peer, packet.attempts, millis())) {
      this->tx_head_ = (this->tx_head_ + 1) % TX_CAPACITY;
      this->tx_count_--;
      this->tx_drops_++;
      this->retry_exhausted_++;
    }
    ESP_LOGD(TAG, "ESP-NOW send rejected: %s", esp_err_to_name(err));
  }
}

}  // namespace esphome::mesh
