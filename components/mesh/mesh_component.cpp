#include "mesh_component.h"
#include "mesh_esp32_lan.h"

#include "esphome/core/hal.h"
#include "esphome/core/application.h"
#include "esphome/core/log.h"

#include <cstring>
#include <esp_random.h>
#include <esp_heap_caps.h>
#include <esp_wifi.h>
#include <lwip/dns.h>
#include <lwip/tcpip.h>

namespace esphome::mesh {

static const char *const TAG = "mesh";
static constexpr uint8_t CONTROL_VERSION = 1;
static constexpr uint8_t CONTROL_WIFI_FAULT = 1;
static constexpr uint8_t CONTROL_WIFI_RECOVER = 2;
static constexpr uint8_t CONTROL_IP_STATUS = 3;
static constexpr uint8_t CONTROL_IP_QUIET_ACK = 4;
static constexpr uint8_t CONTROL_LEASE_PROBE = 5;
static constexpr uint8_t CONTROL_LEASE_RESULT = 6;
static constexpr uint8_t CONTROL_IP_ACK = 7;
#ifdef MESH_IPV6
static constexpr uint8_t CONTROL_IPV6_CLAIM = 0x16;
static constexpr uint8_t CONTROL_IPV6_GRANT = 0x17;
#endif
// Commands 8/9 belonged to the historical exclusive-gateway prototype.
// Endpoint reachability and witnesses now use separate commands 10..13.

MeshComponent *MeshComponent::instance_ = nullptr;

namespace {
class MeshGuard {
 public:
  explicit MeshGuard(SemaphoreHandle_t mutex) : mutex_(mutex) {
    if (mutex_ != nullptr)
      xSemaphoreTakeRecursive(mutex_, portMAX_DELAY);
  }
  ~MeshGuard() {
    if (mutex_ != nullptr)
      xSemaphoreGiveRecursive(mutex_);
  }

 private:
  SemaphoreHandle_t mutex_;
};
}  // namespace

bool MeshComponent::ip_available() const { return this->ip_enabled() && this->ip_netif_.available(); }
bool MeshComponent::ipv4_available() const { return this->ip_enabled() && this->ip_netif_.ipv4_available(); }
#ifdef MESH_IPV6
bool MeshComponent::ipv6_snapshot(::mesh_ip::Ipv6AddressSnapshot &snapshot) const {
  return this->ip_enabled() && this->ip_netif_.local_ipv6_snapshot(snapshot);
}
#endif
uint32_t MeshComponent::ip_address() const { return this->ip_netif_.address(); }
bool MeshComponent::benchmark_active() const {
  MeshGuard guard(this->mutex_);
  return this->benchmark_active_;
}
uint8_t MeshComponent::root_id() const {
  MeshGuard guard(this->mutex_);
  return this->core_ ? this->core_->route().root : 0;
}
uint8_t MeshComponent::parent_id() const {
  MeshGuard guard(this->mutex_);
  return this->core_ ? this->core_->route().parent : 0;
}
uint8_t MeshComponent::rank() const {
  MeshGuard guard(this->mutex_);
  return this->core_ ? this->core_->route().rank : 255;
}
uint8_t MeshComponent::node_id() const {
  MeshGuard guard(this->mutex_);
  return this->node_id_;
}
uint8_t MeshComponent::first_peer_id() const {
  MeshGuard guard(this->mutex_);
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    std::array<uint8_t, 6> mac;
    if (this->transport_.peer_address(node, mac) && this->allowed_(node))
      return node;
  }
  return 0;
}
bool MeshComponent::mesh_connected() const {
  MeshGuard guard(this->mutex_);
  return this->core_ && this->core_->route().connected;
}
bool MeshComponent::mesh_connection_active() const {
  MeshGuard guard(this->mutex_);
  return this->core_ && this->core_->route().connected && this->ip_netif_.available() &&
         this->ip_netif_.fallback_active();
}
bool MeshComponent::wifi_fault_active() const {
  MeshGuard guard(this->mutex_);
  return this->wifi_fault_active_;
}
uint32_t MeshComponent::received_count() const {
  MeshGuard guard(this->mutex_);
  return this->core_ ? this->core_->counters().received : 0;
}
uint32_t MeshComponent::forwarded_count() const {
  MeshGuard guard(this->mutex_);
  return this->core_ ? this->core_->counters().forwarded : 0;
}
uint32_t MeshComponent::tx_drop_count() const {
  MeshGuard guard(this->mutex_);
  return this->tx_drops_ + (this->runtime_ ? this->runtime_->transport_counters().transmit_drops : 0);
}
uint32_t MeshComponent::probe_reply_count() const {
  MeshGuard guard(this->mutex_);
  return this->probe_replies_;
}

uint32_t MeshComponent::rx_drop_count() const {
  MeshGuard guard(this->mutex_);
  return this->rx_drops_.load() +
         (this->runtime_ ? this->runtime_->transport_counters().receive_drops + this->runtime_->counters().policy_drops
                         : 0);
}

bool MeshComponent::transport_has_room_(size_t reserve) const {
  if (!this->runtime_)
    return false;
  const auto queue = this->runtime_->queue_state();
  return queue.capacity > reserve && queue.pending < queue.capacity - reserve;
}

size_t MeshComponent::transport_payload_mtu_() const {
  if (!this->runtime_)
    return 0;
  const size_t native = this->runtime_->interface().capabilities.payload_mtu;
  return native < ::mesh_transport::kProtocolControlPayloadLimit ? native
                                                                 : ::mesh_transport::kProtocolControlPayloadLimit;
}

bool MeshComponent::allowed_(uint8_t node_id) const {
  if (node_id < 1 || node_id > mesh_limits::MAX_NODES || !(this->allowed_nodes_ & (1U << (node_id - 1))))
    return false;
#ifdef USE_MESH_AUTO
  if (this->auto_)
    return !this->auto_->quarantined &&
           (node_id == this->node_id_ || (this->auto_->ready_mask & (1U << (node_id - 1))));
#endif
  return true;
}

uint16_t MeshComponent::known_gateway_mask_() const {
#ifdef USE_MESH_AUTO
  if (this->auto_ && this->auto_->members)
    return this->ip_gateways_ & this->auto_->ready_mask & this->auto_->members->gateway_mask();
#endif
  return this->ip_gateways_;
}

uint64_t MeshComponent::identity_session_(uint8_t node) const {
#ifdef USE_MESH_AUTO
  if (this->auto_ && !this->auto_->quarantined && node >= 1 && node <= mesh_limits::MAX_NODES) {
    const auto &binding = this->auto_->bindings[node - 1];
    if (binding.present && binding.ready)
      return binding.session;
  }
#else
  return this->manual_sessions_.session(node);
#endif
  return 0;
}

bool MeshComponent::initialize_runtime_(bool preserve_ip_replay) {
  this->runtime_ = std::make_unique<::mesh_core::MeshRuntime>(this->node_id_);
  this->core_ = &this->runtime_->core();
  const auto backend = this->transport_.transport();
  const ::mesh_core::TimingProfile timing{};
  const ::mesh_core::MeshRuntime::Observers observers{this, accept_frame_, core_deliver_, core_route_changed_,
                                                      received_frame_};
  if (!this->runtime_->bind(backend, timing, observers,
                            this->ip_enabled() ? ::mesh_transport::kEndpointControlPayloadBudget : 0) ||
      !this->ip_delivery_.configure(
          this->node_id_,
          {::mesh_ip::packet_profile_for_link(backend.interface.capabilities, timing.route_expiry_ms), 250, 2000, 5},
          {this, ip_send_fragment_, ip_send_ack_, ip_accept_packet_}, !preserve_ip_replay))
    return false;
  this->runtime_->set_wake_callback(this, wake_transport_);
  this->core_->set_prefer_root_id(false);
  this->core_->set_route_stability(this->route_stability_);
#ifdef USE_MESH_AUTO
  if (this->auto_ && !this->core_->set_session_resolver(this, auto_session_))
    return false;
#else
  if (!this->core_->set_session_resolver(this, manual_session_) || !this->core_->set_bootstrap_allowed(true))
    return false;
#endif
  return true;
}

void MeshComponent::setup() {
  Esp32WifiPlatform::refresh_native_state();
  Esp32LanPlatform::refresh_native_state();
  if (instance_ != nullptr) {
    ESP_LOGE(TAG, "Only one mesh instance is supported");
    this->mark_failed();
    return;
  }
  instance_ = this;
  this->mutex_ = xSemaphoreCreateRecursiveMutexStatic(&this->mutex_storage_);
  this->benchmark_boot_ = esp_random();
  this->ip_packet_sequence_ = esp_random();
  this->endpoint_session_ = (uint64_t(esp_random()) << 32) | esp_random();
  if (this->endpoint_session_ == 0)
    this->endpoint_session_ = 1;
#ifndef USE_MESH_AUTO
  if (!this->manual_sessions_.configure(this->node_id_, this->endpoint_session_, this->allowed_nodes_)) {
    ESP_LOGE(TAG, "Manual boot-session initialization failed");
    this->mark_failed();
    return;
  }
#endif
  this->radio_ownership_.start_native_acquisition(millis());
  this->last_native_requested_ = Esp32WifiPlatform::native_requested();
  // Native scanning/association owns the PHY before any connectionless SDK
  // setup. Authentication can initialize its portable identity without it.
  this->transport_.set_sdk_enabled(false);
#ifdef USE_MESH_AUTO
  if (this->auto_ &&
      (!this->management_.bind(this->transport_.management_backend(), ::mesh_auto::kMaxDiscoveryWireSize) ||
       !this->auto_setup_())) {
    ESP_LOGE(TAG, "Automatic mesh identity initialization failed");
    this->mark_failed();
    return;
  }
#endif
  this->transport_.set_node_id(this->node_id_);
  if (!this->initialize_runtime_()) {
    this->mark_failed();
    return;
  }
  // An uplink is a route, not a global ownership leader. Each native gateway
  // uses its own LAN; other nodes prefer fewer hops with IDs only as ties.
  if (this->ip_gateway_ != 0 &&
      !this->ip_netif_.configure(this->node_id_, this->ip_gateway_, this->ip_gateways_ != 0, this->ip_gateways_)) {
    ESP_LOGE(TAG, "IP adapter initialization failed");
    this->mark_failed();
    return;
  }
  this->ip_netif_.set_transport_wake(this, wake_transport_);
#ifdef USE_MESH_DISCOVERY
  this->ip_mdns_.setup();
#endif
  if (!Esp32WifiPlatform::native_requested() || Esp32WifiPlatform::disabled())
    this->enter_mesh_radio_();
  this->update_radio_lifecycle_(this->capture_radio_state_(false));
  this->runtime_->start();
  if (!Esp32WifiPlatform::station_address(this->own_mac_)) {
    ESP_LOGE(TAG, "Native endpoint identity unavailable");
    this->mark_failed();
    this->runtime_->stop();
    return;
  }
#ifdef MESH_IPV6
  this->ip_netif_.set_local_mac(this->own_mac_.data());
#endif
  this->transport_exited_.store(false);
  // ESP-NOW requires the previous Wi-Fi send callback to have returned before
  // submitting again. An atomic result alone cannot guarantee that across
  // cores: the worker could observe it while the callback is still returning.
  // Our callbacks do not block; running below the Wi-Fi task on its configured
  // core makes completion consumption and the next submission sequential.
  if (xTaskCreatePinnedToCore(transport_task_, "mesh_ip", 12288, this, 2, &this->transport_task_handle_,
                              WIFI_TASK_CORE_ID) != pdPASS) {
    this->transport_exited_.store(true);
    ESP_LOGE(TAG, "Mesh transport task creation failed");
    this->mark_failed();
    this->runtime_->stop();
    return;
  }
#ifdef USE_MESH_IP
  if (!this->network_provider_.start(this)) {
    this->mark_failed();
    this->transport_stop_.store(true);
  }
#endif
}

bool MeshComponent::accept_frame_(void *context, const ::mesh_transport::ReceiveMetadata &metadata,
                                  const ::mesh_core::Frame &frame) {
  auto *self = static_cast<MeshComponent *>(context);
  self->received_ad_sender_ = self->received_ad_channel_ = 0;
  if (frame.type == ::mesh_core::FrameType::BOOT_SESSION) {
#ifdef USE_MESH_AUTO
    return false;
#else
    ::mesh_session::Message message;
    if (!::mesh_session::decode(frame.payload, frame.payload_length, frame.source, frame.destination, message))
      return false;
#endif
  }
#ifdef USE_MESH_AUTO
  if (self->auto_ &&
      (frame.source_session == 0 || frame.source_session != self->identity_session_(frame.source) ||
       (frame.destination == 0 ? frame.destination_session != 0
                               : frame.destination_session == 0 ||
                                     frame.destination_session != self->identity_session_(frame.destination)) ||
       (frame.root == 0 ? frame.root_session != 0
                        : frame.root_session == 0 || frame.root_session != self->identity_session_(frame.root))))
    return false;
#endif
#ifndef USE_MESH_AUTO
  if (frame.type != ::mesh_core::FrameType::BOOT_SESSION &&
      (frame.source_session == 0 || frame.source_session != self->identity_session_(frame.source) ||
       (frame.destination == 0 ? frame.destination_session != 0
                               : frame.destination_session == 0 ||
                                     frame.destination_session != self->identity_session_(frame.destination)) ||
       (frame.root == 0 ? frame.root_session != 0
                        : frame.root_session == 0 || frame.root_session != self->identity_session_(frame.root))))
    return false;
#endif
  const bool accepted = self->allowed_(metadata.immediate_sender) && self->allowed_(frame.source) &&
                        (frame.destination == 0 || self->allowed_(frame.destination)) &&
                        (frame.root == 0 || self->allowed_(frame.root));
  if (accepted && frame.type == ::mesh_core::FrameType::ADVERTISEMENT && frame.source == metadata.immediate_sender &&
      metadata.channel >= 1 && metadata.channel <= 14) {
    self->received_ad_sender_ = metadata.immediate_sender;
    self->received_ad_channel_ = static_cast<uint8_t>(metadata.channel);
  }
  return accepted;
}

void MeshComponent::received_frame_(void *context, uint32_t) {
  // DHCP processing can sample a newer clock while delivering a frame.
  auto *self = static_cast<MeshComponent *>(context);
  const uint32_t now = millis();
  const auto &route = self->core_->route();
  if (route.connected && !route.direct)
    self->radio_ownership_.observe_parent_channel(now, self->received_ad_sender_, route.parent,
                                                  self->received_ad_channel_);
  self->select_ip_gateway_(now);
}

void MeshComponent::core_deliver_(void *context, const ::mesh_core::Frame &frame) {
  static_cast<MeshComponent *>(context)->deliver_(frame);
}

void MeshComponent::deliver_(const ::mesh_core::Frame &frame) {
#ifndef USE_MESH_AUTO
  if (frame.type == ::mesh_core::FrameType::BOOT_SESSION) {
    this->manual_session_receive_(frame);
    return;
  }
#endif
  if (frame.type == ::mesh_core::FrameType::DATA && this->ip_enabled()) {
    this->ip_deliver_(frame);
    return;
  }
  if (frame.type == ::mesh_core::FrameType::PROBE || frame.type == ::mesh_core::FrameType::PROBE_REPLY) {
    if (frame.type == ::mesh_core::FrameType::PROBE_REPLY) {
      this->probe_replies_++;
      for (auto &pending : this->pending_probes_) {
        if (!pending.used || pending.sequence != frame.sequence || pending.peer != frame.source)
          continue;
        if (pending.run != 0) {
          bool valid_payload = frame.payload_length == BENCHMARK_PAYLOAD_SIZE;
          for (size_t i = 0; valid_payload && i < BENCHMARK_PAYLOAD_SIZE; i++)
            valid_payload = frame.payload[i] == static_cast<uint8_t>(i);
          if (!valid_payload) {
            ESP_LOGW(TAG, "Benchmark reply payload mismatch, seq=%u", frame.sequence);
            break;  // Leave this request pending; it will expire as a timeout.
          }
        }
        const uint32_t rtt_us = micros() - pending.sent_us;
        if (pending.run != 0) {
          if (rtt_us >= PROBE_TIMEOUT_MS * 1000U) {
            ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=timeout seq=%u peer=%u timeout_ms=%u",
                     static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(pending.run),
                     frame.sequence, frame.source, static_cast<unsigned>(PROBE_TIMEOUT_MS));
          } else {
            ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=reply seq=%u peer=%u rtt_us=%u",
                     static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(pending.run),
                     frame.sequence, frame.source, static_cast<unsigned>(rtt_us));
          }
        }
        pending.used = false;
        break;
      }
    }
    ESP_LOGI(TAG, "%s from=%u to=%u seq=%u ttl=%u",
             frame.type == ::mesh_core::FrameType::PROBE ? "PROBE" : "PROBE_REPLY", frame.source, frame.destination,
             frame.sequence, frame.ttl);
  } else if (frame.type == ::mesh_core::FrameType::CONTROL) {
    if (this->ip_enabled() && frame.payload_length == ::mesh_ip::kDeliveryAckSize + 2 &&
        frame.payload[0] == CONTROL_VERSION && frame.payload[1] == CONTROL_IP_ACK) {
      this->ip_delivery_.accept_ack(frame.source, frame.payload + 2, frame.payload_length - 2, millis());
      return;
    }
#ifdef MESH_IPV6
    if (this->ip_enabled() && this->ipv6_control_(frame))
      return;
#endif
    if (this->ip_gateways_ != 0 && this->endpoint_deliver_(frame))
      return;
#ifdef USE_MESH_DISCOVERY
    if (this->gateway_service_() && frame.payload_length >= 2 &&
        (frame.payload[0] == CONTROL_VERSION || frame.payload[0] == 2
#ifdef MESH_IPV6
         || frame.payload[0] == 3
#endif
         ) &&
        frame.payload[1] == ::mesh_ip::DISCOVERY_CONTROL) {
      this->ip_mdns_.enqueue(frame.source, frame.payload, frame.payload_length);
      return;
    }
#endif
#ifndef MESH_IP_CLIENT_ONLY
    if (this->ip_gateway_ != 0 && frame.payload_length == 10 && frame.payload[0] == CONTROL_VERSION &&
        frame.payload[1] == CONTROL_LEASE_PROBE && this->gateway_service_()) {
      uint32_t nonce = 0, address;
      for (size_t i = 0; i < 4; i++)
        nonce |= uint32_t(frame.payload[2 + i]) << (8 * i);
      std::memcpy(&address, frame.payload + 6, 4);
      this->ip_netif_.begin_lease_probe(frame.source, address, nonce);
      return;
    }
#endif
    if (this->ip_gateway_ != 0 && frame.payload_length == 11 && frame.payload[0] == CONTROL_VERSION &&
        frame.payload[1] == CONTROL_LEASE_RESULT && frame.source == this->ip_gateway_ && this->dhcp_probe_pending_ &&
        frame.payload[10] <= 1 && (this->ip_gateways_ == 0 || this->dhcp_quiet_.ready(millis()))) {
      uint32_t nonce = 0, address;
      for (size_t i = 0; i < 4; i++)
        nonce |= uint32_t(frame.payload[2 + i]) << (8 * i);
      std::memcpy(&address, frame.payload + 6, 4);
      if (nonce == this->dhcp_client_.xid() && address == lwip_htonl(this->dhcp_client_.lease().address) &&
          this->dhcp_client_.lease_valid(millis())) {
        if (frame.payload[10] == 0)
          this->accept_mesh_lease_();
        else {
          ESP_LOGW(TAG, "IP_LEASE conflict: decline candidate and retry DHCP");
          this->dhcp_client_.decline(millis());
          this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
          this->dhcp_quiet_.cancel();
          this->ip_netif_.clear_mesh_lease();
        }
      }
      return;
    }
    if (this->ip_status_deliver_(frame) || this->ip_quiet_ack_deliver_(frame))
      return;
    if (frame.payload_length != 6 || frame.payload[0] != CONTROL_VERSION ||
        (frame.payload[1] != CONTROL_WIFI_FAULT && frame.payload[1] != CONTROL_WIFI_RECOVER)) {
      ESP_LOGW(TAG, "Invalid lab control from %u", frame.source);
      return;
    }
    uint32_t duration = 0;
    for (size_t i = 0; i < 4; i++)
      duration |= uint32_t(frame.payload[2 + i]) << (8 * i);
    this->pending_command_ = frame.payload[1];
    this->pending_duration_ = duration;
    ESP_LOGI(TAG, "CONTROL from=%u seq=%u command=%u duration=%u ms", frame.source, frame.sequence,
             this->pending_command_, static_cast<unsigned>(duration));
  }
}

bool MeshComponent::ip_status_deliver_(const ::mesh_core::Frame &frame) {
  if ((this->ip_gateways_ == 0 && this->ip_gateway_ == 0) ||
      (frame.payload_length != 7 && frame.payload_length != 11) || frame.payload[0] != CONTROL_VERSION ||
      frame.payload[1] != CONTROL_IP_STATUS ||
      !((frame.payload_length == 7 && frame.payload[6] <= 1) || (frame.payload_length == 11 && frame.payload[6] == 2)))
    return false;
  // These packets carry no challenge freshness. In candidate mode even a
  // delayed native/quiet status must not revoke a newer endpoint proof.
  if (this->ip_gateways_ != 0)
    return true;
#ifndef MESH_IP_CLIENT_ONLY
  if (this->gateway_service_()) {
    uint32_t address;
    std::memcpy(&address, frame.payload + 2, 4);
    const bool accepted = this->ip_netif_.set_peer(frame.source, address, frame.payload[6] == 1);
#ifdef USE_MESH_DISCOVERY
    if (accepted)
      this->ip_mdns_.note_status(frame.source, address, frame.payload[6] == 1);
#endif
    if (accepted && frame.payload[6] == 2) {
      auto &ack = this->pending_ip_acks_[frame.source - 1];
      std::memcpy(ack.payload, frame.payload, sizeof(ack.payload));
      ack.payload[1] = CONTROL_IP_QUIET_ACK;
      ack.payload[6] = 0;
      ack.used = true;
    }
  }
#endif
  return true;
}

bool MeshComponent::ip_quiet_ack_deliver_(const ::mesh_core::Frame &frame) {
  if (frame.payload_length != 11 || frame.payload[0] != CONTROL_VERSION || frame.payload[1] != CONTROL_IP_QUIET_ACK ||
      frame.payload[6] != 0)
    return false;
  const bool permitted = this->ip_gateways_ != 0 ? this->gateway_candidate_(frame.source)
                                                 : this->ip_gateway_ != 0 && frame.source == this->ip_gateway_;
  if (!permitted)
    return true;
  uint32_t address, nonce = 0;
  std::memcpy(&address, frame.payload + 2, 4);
  for (size_t i = 0; i < 4; i++)
    nonce |= uint32_t(frame.payload[7 + i]) << (8 * i);
  if (this->ip_gateways_ != 0 && this->dhcp_probe_pending_ && this->dhcp_quiet_.waiting() &&
      address == lwip_htonl(this->dhcp_client_.lease().address))
    this->dhcp_quiet_.acknowledge(frame.source, nonce, millis());
  if (address != this->ip_handover_address_)
    return true;
  if (this->ip_gateways_ != 0)
    this->ip_handover_.acknowledge(frame.source, nonce, millis());
  else
    this->ip_handover_.acknowledge(nonce, millis());
  return true;
}

void MeshComponent::ip_quiet_ack_tick_(uint32_t now) {
#ifndef MESH_IP_CLIENT_ONLY
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    auto &ack = this->pending_ip_acks_[i];
    if (!ack.used || this->ip_netif_.peer_mesh_address(i + 1) != 0)
      continue;
#ifdef USE_MESH_DISCOVERY
    // ACK only after both the forwarding gate and asynchronous delegated
    // responder have stopped. A root change is not a withdrawal proof.
    if (this->ip_mdns_.announced(i + 1))
      continue;
#endif
    if (this->core_->send_control(i + 1, ++this->sequence_, ack.payload, sizeof(ack.payload), now))
      ack.used = false;
  }
#else
  (void) now;
#endif
}

void MeshComponent::core_route_changed_(void *context, const ::mesh_core::RouteSnapshot &route) {
  auto *self = static_cast<MeshComponent *>(context);
  ESP_LOGI(TAG, "ROUTE node=%u connected=%s direct=%s root=%u parent=%u rank=%u path=0x%04X", self->node_id_,
           YESNO(route.connected), YESNO(route.direct), route.root, route.parent, route.rank, route.path_bits);
}

void MeshComponent::loop() {
  Esp32WifiPlatform::refresh_native_state();
  Esp32LanPlatform::refresh_native_state();
#ifdef USE_MESH_AUTO
  this->auto_loop_();
#endif
#ifdef USE_MESH_DISCOVERY
  this->discovery_loop_();
#endif
  // Reserve and drain the one TX slot before a bounded single-channel AP probe.
  // RX callbacks remain live; the worker pauses SDK/core mutation during scan.
  this->maybe_probe_wifi_();
  this->maybe_search_channel_();
  MeshGuard guard(this->mutex_);
  if (!this->core_)
    return;
  // The bounded radio scan above can advance beyond the cached loop start.
  const uint32_t now = millis();
  if (this->radio_start_pending_ && uint32_t(now - this->last_radio_start_) >= 1000) {
    this->last_radio_start_ = now;
    this->start_unassociated_radio_();
  }
  if (!this->shutdown_requested_.load() && !Esp32WifiPlatform::native_requested()) {
    if (this->native_recover_pending_ || this->ip_handover_.quiet() || this->wifi_fault_active_)
      this->cancel_native_recovery_();
    if (!this->mesh_radio_active_)
      this->enter_mesh_radio_();
  }
  if (!this->mesh_radio_active_ && !this->wifi_fault_active_ &&
      !(Esp32WifiPlatform::connected() && Esp32WifiPlatform::associated()) &&
      this->radio_ownership_.fallback_due(now,
                                          this->core_->route().connected && this->core_->route().root != this->node_id_,
                                          Esp32WifiPlatform::roaming()))
    this->enter_mesh_radio_();
  if (this->native_recover_pending_) {
    this->finish_wifi_recover_();
  } else if (this->ip_handover_.ready(now)) {
    this->ip_handover_.rejoining();
    this->finish_wifi_recover_();
  }
  if (this->wifi_fault_active_ && now - this->wifi_fault_started_ >= this->wifi_fault_duration_)
    this->clear_wifi_fault();
  if (this->pending_command_ != 0) {
    const uint8_t command = this->pending_command_;
    this->pending_command_ = 0;
    if (command == CONTROL_WIFI_FAULT)
      this->start_wifi_fault(this->pending_duration_);
    else
      this->clear_wifi_fault();
  }
}

void MeshComponent::wake_transport_(void *context) {
  auto *self = static_cast<MeshComponent *>(context);
  // Keep a snapshotted handle alive across TCP/IP and Wi-Fi task callbacks.
  // Closing the handle before waiting for readers prevents notification of a
  // deleted task even when an already captured callback arrives late.
  self->transport_wake_users_.fetch_add(1);
  const auto handle = self->transport_wake_handle_.load();
  if (handle != nullptr)
    xTaskNotifyGive(handle);
  self->transport_wake_users_.fetch_sub(1);
}

void MeshComponent::transport_task_(void *context) {
  auto *self = static_cast<MeshComponent *>(context);
  self->transport_wake_handle_.store(xTaskGetCurrentTaskHandle());
  ESP_LOGI(TAG, "RADIO_TASK core=%u wifi_core=%u priority=%u", static_cast<unsigned>(xPortGetCoreID()),
           static_cast<unsigned>(WIFI_TASK_CORE_ID), static_cast<unsigned>(uxTaskPriorityGet(nullptr)));
  uint8_t immediate_wakes = 0;
  while (!self->transport_stop_.load()) {
    self->transport_tick_();
    // RX, TX completion and IP queue publication wake immediately. The bounded
    // timeout services ACK/expiry clocks when no external event arrives.
    if (ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10) != 0 ? pdMS_TO_TICKS(10) : 1) == 0) {
      immediate_wakes = 0;
    } else if (++immediate_wakes >= 8) {
      // Continuous traffic must also leave time for the lower-priority main
      // loop, particularly on single-core targets.
      vTaskDelay(1);
      immediate_wakes = 0;
    }
  }
  // The worker owns the final SDK teardown too. A stalled driver cannot block
  // the application thread; ESPHome bounds teardown() before rebooting.
  self->update_roaming_suppression_(false);
  self->runtime_->stop();
  while (!self->transport_.sdk_quiescent()) {
    // Preserve ownership and the task until SDK teardown really completes.
    // ESPHome's existing outer teardown deadline still bounds reboot waiting.
    self->transport_.set_sdk_enabled(false);
    vTaskDelay(1);
  }
  self->runtime_->set_wake_callback(nullptr, nullptr);
  self->ip_netif_.set_transport_wake(nullptr, nullptr);
  self->transport_wake_handle_.store(nullptr);
  while (self->transport_wake_users_.load() != 0)
    vTaskDelay(1);
  self->transport_exited_.store(true);
  vTaskDelete(nullptr);
}

void MeshComponent::transport_tick_() {
  MeshGuard guard(this->mutex_);
  // The main task changes the PHY outside this mutex only after TX drains.
  // Freeze all worker SDK/core activity until that short operation completes.
  if (this->channel_switch_active_)
    return;
  uint32_t now = millis();
  const bool status_due = now - this->last_status_ >= 5000;
  const auto radio = this->capture_radio_state_(status_due);
  const bool associated = radio.associated;
  const bool native_connected = radio.native_connected;
  const bool roaming = radio.native_roaming;
  const bool wifi_direct = !this->wifi_fault_active_ && !this->mesh_radio_active_ && associated && native_connected;
  const auto uplink = Esp32LanPlatform::select_uplink(wifi_direct);
  const bool direct = wifi_direct || Esp32LanPlatform::ethernet_connected();
  const bool direct_edge = direct && !this->last_direct_uplink_;
  if (!this->wifi_fault_active_ && !this->mesh_radio_active_)
    this->radio_ownership_.observe_native(now, associated && native_connected);
  this->update_roaming_suppression_(!this->shutdown_requested_.load() && wifi_direct && this->ip_enabled() &&
                                    this->ip_netif_.has_active_mesh_clients());
  this->update_radio_lifecycle_(radio);
  this->shutdown_tick_(now);
#ifdef USE_MESH_AUTO
  if (this->auto_) {
    this->auto_tick_(now, direct);
    if (this->auto_->quarantined) {
      this->runtime_->process(now, this->radio_tx_allowed_(radio));
      return;
    }
  }
#endif
  if (direct_edge && wifi_direct) {
    // The lifecycle gate already tore down the old SDK before acquisition.
    // Its next successful start reinstalls all currently admitted peer keys.
    ESP_LOGI(TAG, "RADIO Wi-Fi connected: refresh encrypted ESP-NOW peers");
  }
  if (this->ip_gateways_ != 0 && this->last_direct_uplink_ && !direct) {
    this->gateway_revalidate_ = true;
    // Native STA ownership ends locally; no remote proxy release is needed.
    this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
    this->dhcp_quiet_.cancel();
  }
  this->last_direct_uplink_ = direct;
  // Every candidate advertises its own working LAN exit. Non-gateway nodes
  // choose a path independently; endpoint addresses do not depend on that root.
  const bool eligible = !this->ip_enabled() || (this->ip_gateways_ != 0 ? this->gateway_candidate_(this->node_id_)
                                                                        : this->node_id_ == this->ip_gateway_);
  this->core_->set_direct_uplink(direct && eligible, now);
  this->select_ip_gateway_(now);
  this->runtime_->poll(now, 48);
  // RX can advance endpoint/DHCP clocks. Subsequent phases must never return
  // to the timestamp captured before delivery (including across uint32 wrap).
  now = millis();
#ifndef USE_MESH_AUTO
  this->manual_session_tick_(now);
#endif
#ifndef MESH_IP_CLIENT_ONLY
  this->ip_quiet_ack_tick_(now);
  ::mesh_ip::MeshIpNetif::LeaseProbeResult proof;
  while (this->ip_netif_.pop_probe_result(proof)) {
    auto &pending = this->pending_lease_results_[proof.node_id - 1];
    pending.payload[0] = CONTROL_VERSION;
    pending.payload[1] = CONTROL_LEASE_RESULT;
    for (size_t i = 0; i < 4; i++)
      pending.payload[2 + i] = (proof.nonce >> (8 * i)) & 0xff;
    std::memcpy(pending.payload + 6, &proof.address, 4);
    pending.payload[10] = proof.conflict ? 1 : 0;
    pending.used = true;
  }
  for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
    auto &pending = this->pending_lease_results_[i];
    if (pending.used && this->core_->send_control(i + 1, ++this->sequence_, pending.payload, 11, now))
      pending.used = false;
  }
#endif
  if (this->ip_enabled())
    // RX callbacks can advance the DHCP lease clock; never tick it with the
    // timestamp captured before receiving the ACK (unsigned wrap looks expired).
    this->ip_tick_(millis(), direct);
  this->benchmark_tick_(millis());
  this->runtime_->tick(millis());
  this->select_ip_gateway_(millis());
  this->runtime_->process(millis(), this->radio_tx_allowed_(radio));
  const uint8_t primary = this->refresh_radio_channel_(wifi_direct, roaming, status_due || direct_edge);
  if (status_due) {
    this->last_status_ = now;
    this->diagnostic_phase_ = 1;
    // USB logging can truncate lines during OTA. Keep every path-proof field
    // within the first 115 bytes, including the logger prefix.
    ESP_LOGI(TAG,
             "STATUS node=%u sta_associated=%s uplink=%s fault=%s root=%u parent=%u rank=%u channel=%u rx=%u fwd=%u "
             "rx_drop=%u tx_drop=%u tx_fail=%u replies=%u",
             this->node_id_, YESNO(associated), YESNO(direct), YESNO(this->wifi_fault_active_), this->root_id(),
             this->parent_id(), this->rank(), primary, static_cast<unsigned>(this->received_count()),
             static_cast<unsigned>(this->forwarded_count()), static_cast<unsigned>(this->rx_drop_count()),
             static_cast<unsigned>(this->tx_drop_count()),
             static_cast<unsigned>(this->runtime_->transport_counters().failed),
             static_cast<unsigned>(this->probe_replies_));
    const auto native_ip = Esp32LanPlatform::native_ip(uplink);
#ifdef MESH_HAS_ETHERNET
    ESP_LOGI(TAG, "LAN node=%u interface=%s connected=%s", this->node_id_,
             uplink == ::mesh_ip::NativeUplink::NATIVE_UPLINK_ETHERNET ? "ethernet" : "wifi", YESNO(direct));
#endif
    ESP_LOGI(TAG, "RADIO node=%u associated=%u native=%u mesh=%u sdk=%u ip=%08X", this->node_id_,
             static_cast<unsigned>(associated), static_cast<unsigned>(native_connected),
             static_cast<unsigned>(this->mesh_radio_active_), static_cast<unsigned>(this->transport_.ready()),
             static_cast<unsigned>(native_ip.address));
  }
  // ESPHome's stock worker-log queue is bounded. Spread diagnostics across
  // the cycle so the MAC/status/memory/IP burst cannot starve API log delivery.
  // A delayed worker emits one phase per tick instead of flushing a backlog.
  const uint32_t diagnostic_age = now - this->last_status_;
  if (this->diagnostic_phase_ == 1 && diagnostic_age >= 1000) {
    this->diagnostic_phase_ = 2;
    ESP_LOGI(TAG,
             "MEMORY node=%u internal_free=%u internal_min=%u internal_block=%u psram_free=%u worker_stack_min=%u "
             "component=%u",
             this->node_id_, static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
             static_cast<unsigned>(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
             static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
             static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)),
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)), static_cast<unsigned>(sizeof(*this)));
    // Keep both actual-task watermarks visible in the short OTA emergency log.
    const uint32_t tcpip_stack = this->ip_netif_.tcpip_stack_min();
    if (tcpip_stack != 0) {
      ESP_LOGI(TAG, "STACK worker=%u tcpip=%u", static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)),
               static_cast<unsigned>(tcpip_stack));
    }
  } else if (this->diagnostic_phase_ == 2 && diagnostic_age >= 2000) {
    this->diagnostic_phase_ = 3;
    if (this->ip_enabled()) {
      // Keep path proof first and short; the stock worker-log buffer is bounded.
      ip4_addr_t ip{this->ip_netif_.address()};
      ESP_LOGI(TAG, "IP_STATUS node=%u address=%s available=%s fallback=%s worker=YES gateway=%u", this->node_id_,
               ip4addr_ntoa(&ip), YESNO(this->ip_netif_.available()), YESNO(this->ip_netif_.fallback_active()),
               this->ip_gateway_);
      const auto counters = this->ip_netif_.counters();
      const auto &delivery = this->ip_delivery_.counters();
      const auto &delivery_profile = this->ip_delivery_.profile();
      ESP_LOGI(TAG, "IP_ACK window=%u batch=%u delay_ms=%u", static_cast<unsigned>(::mesh_ip::kDeliveryWindow),
               static_cast<unsigned>(delivery_profile.ack_batch_size),
               static_cast<unsigned>(delivery_profile.max_ack_delay_ms));
      // Short records survive ESPHome's emergency logger during OTA. Queue
      // rejection attempts are separate from exhausted accepted datagrams.
      ESP_LOGI(TAG, "IP_TX ack=%u retry=%u expired=%u exhausted=%u", static_cast<unsigned>(delivery.acknowledged),
               static_cast<unsigned>(delivery.fragment_retries), static_cast<unsigned>(delivery.tx_expired),
               static_cast<unsigned>(delivery.retry_exhausted));
      ESP_LOGI(TAG, "IP_RX delivered=%u busy=%u pending=%u", static_cast<unsigned>(delivery.delivered),
               static_cast<unsigned>(delivery.receive_busy), static_cast<unsigned>(this->ip_delivery_.pending_count()));
      ESP_LOGI(TAG, "IP_QUEUE flow_busy=%u rx_retry=%u drop=%u", static_cast<unsigned>(counters.flow_backpressure),
               static_cast<unsigned>(counters.rx_retries), static_cast<unsigned>(counters.queue_drops));
      ESP_LOGI(TAG, "RADIO_QUEUE expired=%u exhausted=%u", static_cast<unsigned>(this->transport_.queue_expiry_count()),
               static_cast<unsigned>(this->transport_.retry_exhausted_count()));
    }
  } else if (this->diagnostic_phase_ == 3 && diagnostic_age >= 3000) {
    this->diagnostic_phase_ = 4;
    Esp32WifiPlatform::PowerSave actual = Esp32WifiPlatform::PowerSave::UNKNOWN;
    Esp32WifiPlatform::actual_power_save(actual);
    // Put observed driver mode and successful RX-policy setup first: ESPHome
    // may use its short emergency USB logger while the main task handles OTA.
    // AUTO records bind this routing ID to the authenticated station MAC.
    ESP_LOGI(TAG,
             "RADIO_POWER node=%u actual=%s receive_ready=%s configured=%s effective=%s rx_window=%u interval=%u "
             "wake_schedule=NO",
             this->node_id_, Esp32WifiPlatform::power_save_name(actual),
             YESNO(this->transport_.continuous_receive_ready()),
             Esp32WifiPlatform::power_save_name(Esp32WifiPlatform::configured_power_save()),
             Esp32WifiPlatform::power_save_name(Esp32WifiPlatform::effective_power_save()),
             static_cast<unsigned>(EspNowTransport::RECEIVE_WINDOW_MS),
             static_cast<unsigned>(EspNowTransport::RECEIVE_INTERVAL_MS));
  } else if (this->diagnostic_phase_ == 4 && diagnostic_age >= 4000) {
    this->diagnostic_phase_ = 5;
#if ESPHOME_LOG_LEVEL >= ESPHOME_LOG_LEVEL_DEBUG
    if (this->ip_enabled()) {
      const auto counters = this->ip_netif_.counters();
      // Detailed counters use a separate phase instead of crowding out path proof.
      ESP_LOGD(TAG,
               "IP_STATS sent=%u received=%u reassembly_drop=%u queued=%u delivered=%u queue_drop=%u invalid=%u "
               "proxy_arp=%u lan_tx=%u",
               static_cast<unsigned>(this->ip_sent_), static_cast<unsigned>(this->ip_received_),
               static_cast<unsigned>(this->ip_reassembly_drops_), static_cast<unsigned>(counters.mesh_tx),
               static_cast<unsigned>(counters.mesh_rx), static_cast<unsigned>(counters.queue_drops),
               static_cast<unsigned>(counters.invalid_packets), static_cast<unsigned>(counters.proxy_arp),
               static_cast<unsigned>(counters.lan_tx));
    }
#endif
    // One peer per cycle keeps diagnostics bounded even with a full mesh.
    // Applied SDK configuration and actual successful callback rates are
    // separate evidence; older SDK callbacks cannot observe the latter.
    for (size_t attempt = 0; attempt < ::mesh_core::kMaxNodes; attempt++) {
      const uint8_t peer = this->radio_rate_diagnostic_node_;
      this->radio_rate_diagnostic_node_ = peer % ::mesh_core::kMaxNodes + 1;
      EspNowTransport::PeerRateStats rate;
      if (!this->transport_.peer_rate(peer, rate))
        continue;
      const char *configured = rate.configured == EspNowTransport::PeerRate::BASE   ? "BASE"
                               : rate.configured == EspNowTransport::PeerRate::FAST ? "FAST"
                                                                                    : "UNKNOWN";
      ESP_LOGI(TAG, "RADIO_RATE peer=%u configured=%s probes=%u fallback=%u errors=%u", peer, configured,
               static_cast<unsigned>(this->transport_.rate_probe_count()),
               static_cast<unsigned>(this->transport_.rate_fallback_count()),
               static_cast<unsigned>(this->transport_.rate_error_count()));
      ESP_LOGI(TAG, "RADIO_PHY peer=%u supported=%s fast_tx=%u base_tx=%u", peer,
               YESNO(EspNowTransport::rate_observation_supported()), static_cast<unsigned>(rate.observed_fast_success),
               static_cast<unsigned>(rate.observed_base_success));
      break;
    }
  }
}

void MeshComponent::drop_obsolete_ip_tx_() {
  // Old selection's data is obsolete; retain outstanding retry/callback state.
  this->runtime_->cancel_pending();
}

void MeshComponent::select_ip_gateway_(uint32_t now) {
  if (this->ip_gateways_ == 0)
    return;
  const auto &route = this->core_->route();
  const uint8_t selected = route.connected && this->gateway_candidate_(route.root) ? route.root : 0;
  if (selected == this->ip_gateway_)
    return;
  const uint8_t previous = this->ip_gateway_;
  this->ip_gateway_ = selected;
  this->ip_netif_.select_gateway(selected);
  // Endpoint identity and the DHCP clock survive every route-only transition.
  // Only an unfinished first lease needs another ACK/probe-capable gateway.
  if (selected != 0 && selected != this->node_id_ && !this->dhcp_lease_installed_)
    this->gateway_revalidate_ = true;
  this->ip_delivery_.reset(false);
  this->drop_obsolete_ip_tx_();
#ifdef MESH_IPV6
  this->last_ipv6_status_ = now - 500;
  if (previous != 0 && previous != this->node_id_) {
    ::mesh_ip::Ipv6AddressSnapshot old;
    if (this->ip_netif_.local_ipv6_claim(old) && old.generation != 0) {
      uint8_t withdraw[8]{CONTROL_VERSION, CONTROL_IPV6_CLAIM, 0, 0};
      uint32_t revision = old.generation + 1;
      if (revision == 0)
        revision = 1;
      for (size_t i = 0; i < 4; ++i)
        withdraw[4 + i] = static_cast<uint8_t>(revision >> (8 * i));
      this->core_->send_control(previous, ++this->sequence_, withdraw, sizeof(withdraw), now);
    }
  }
#endif
  this->last_ip_status_ = now - 500;
  ESP_LOGI(TAG, "IP_GATEWAY path previous=%u selected=%u lease_preserved=%s", previous, selected,
           YESNO(this->dhcp_lease_installed_ && this->dhcp_client_.lease_valid(now)));
}

void MeshComponent::ip_tick_(uint32_t now, bool associated) {
  this->dhcp_tick_(now, associated);
  now = millis();
  if (associated) {
    this->ip_handover_.connected();
#ifdef MESH_HAS_ETHERNET
    // A cable return is independent of the managed Wi-Fi handover. Stop the
    // mesh DHCP identity before Ethernet's own DHCP client supplies the LAN IP.
    if (Esp32LanPlatform::ethernet_connected()) {
      this->dhcp_client_.stop();
      this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
      this->dhcp_quiet_.cancel();
    }
#endif
    if (this->native_handover_attempt_)
      this->dhcp_client_.stop();
    this->native_handover_attempt_ = false;
  }
  if (now - this->last_ip_update_ >= 100) {
    this->last_ip_update_ = now;
    const bool wifi_direct = !this->wifi_fault_active_ && !this->mesh_radio_active_ && Esp32WifiPlatform::connected() &&
                             Esp32WifiPlatform::associated();
    const auto uplink = Esp32LanPlatform::select_uplink(wifi_direct);
    const auto info = Esp32LanPlatform::native_ip(uplink);
    this->ip_netif_.update(info.address, info.netmask, info.gateway, associated, this->core_->route().connected,
                           uplink);
  }
  this->endpoint_tick_(now, associated);
#ifdef MESH_IPV6
  this->ipv6_tick_(now, associated);
#endif
  if (this->ip_gateways_ == 0 && this->ip_gateway_ != 0 && this->node_id_ != this->ip_gateway_ &&
      this->ip_netif_.address() != 0 &&
      (associated || this->ip_handover_.quiet() ||
       (!this->gateway_revalidate_ && (this->ip_gateways_ == 0 || this->dhcp_lease_installed_))) &&
      now - this->last_ip_status_ >= (this->ip_handover_.waiting() ? 100U : 500U)) {
    this->last_ip_status_ = now;
    uint8_t status[11]{CONTROL_VERSION, CONTROL_IP_STATUS};
    const uint32_t address = this->ip_netif_.address();
    std::memcpy(status + 2, &address, 4);
    status[6] = this->ip_handover_.quiet() ? 2 : (associated ? 0 : 1);
    const uint32_t nonce = this->ip_handover_.nonce();
    for (size_t i = 0; i < 4; i++)
      status[7 + i] = (nonce >> (8 * i)) & 0xff;
    this->core_->send_control(this->ip_gateway_, ++this->sequence_, status, this->ip_handover_.quiet() ? 11 : 7, now);
  }
#ifdef USE_MESH_DISCOVERY
  this->discovery_tick_(now, associated);
#endif
  while (this->ip_delivery_.can_begin()) {
    ::mesh_ip::PacketDelivery::TxReservation reservation;
    if (!this->ip_delivery_.reserve(reservation))
      break;
    ::mesh_ip::QueuedIpMetadata packet;
    auto *target = this->ip_delivery_.reserved_data(reservation);
    if (target == nullptr || !this->ip_netif_.consume_outgoing(target, ::mesh_ip::kMtu, packet)) {
      this->ip_delivery_.cancel(reservation);
      break;
    }
    if (!this->ip_delivery_.commit(reservation, packet.destination, packet.length, ++this->ip_packet_sequence_, now,
                                   packet.ingress_source))
      this->tx_drops_++;
  }
  this->ip_delivery_.tick(now);
  this->ip_sent_ = this->ip_delivery_.counters().acknowledged;
  this->ip_received_ = this->ip_delivery_.counters().delivered;
}

#ifdef MESH_IPV6
bool MeshComponent::ipv6_control_(const ::mesh_core::Frame &frame) {
  if (frame.payload_length < 2 || frame.payload[0] != CONTROL_VERSION ||
      (frame.payload[1] != CONTROL_IPV6_CLAIM && frame.payload[1] != CONTROL_IPV6_GRANT))
    return false;
  if (frame.payload_length < 8 || (frame.payload[2] & ~1U) != 0 ||
      frame.payload[3] > ::mesh_ip::Ipv6AddressSnapshot::CAPACITY ||
      frame.payload_length != 8 + size_t(frame.payload[3]) * 16)
    return true;
  ::mesh_ip::Ipv6AddressSnapshot snapshot;
  snapshot.count = frame.payload[3];
  snapshot.ready = (frame.payload[2] & 1) != 0;
  for (size_t i = 0; i < 4; ++i)
    snapshot.generation |= uint32_t(frame.payload[4 + i]) << (8 * i);
  if (snapshot.generation == 0)
    return true;
  for (size_t i = 0; i < snapshot.count; ++i)
    std::memcpy(snapshot.addresses[i].bytes.data(), frame.payload + 8 + i * 16, 16);
  if (frame.payload[1] == CONTROL_IPV6_CLAIM) {
    if (this->gateway_service_() && this->last_direct_uplink_)
      this->ip_netif_.apply_peer_ipv6_claim(frame.source, snapshot, snapshot.ready);
  } else
    this->ip_netif_.accept_ipv6_grant(frame.source, snapshot);
  return true;
}

void MeshComponent::ipv6_tick_(uint32_t now, bool direct) {
  if (uint32_t(now - this->last_ipv6_status_) < 500)
    return;
  this->last_ipv6_status_ = now;
  const auto send = [&](uint8_t destination, uint8_t opcode, const ::mesh_ip::Ipv6AddressSnapshot &snapshot,
                        bool flag) {
    uint8_t bytes[8 + 16 * ::mesh_ip::Ipv6AddressSnapshot::CAPACITY]{CONTROL_VERSION, opcode,
                                                                     static_cast<uint8_t>(flag), snapshot.count};
    for (size_t i = 0; i < 4; ++i)
      bytes[4 + i] = static_cast<uint8_t>(snapshot.generation >> (8 * i));
    for (size_t i = 0; i < snapshot.count; ++i)
      std::memcpy(bytes + 8 + i * 16, snapshot.addresses[i].bytes.data(), 16);
    return this->core_->send_control(destination, ++this->sequence_, bytes, 8 + size_t(snapshot.count) * 16, now);
  };
  if (direct && this->gateway_service_()) {
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
      ::mesh_ip::Ipv6AddressSnapshot snapshot;
      const bool current = this->ip_netif_.peer_ipv6_snapshot(node, snapshot) && snapshot.generation != 0;
#ifdef USE_MESH_DISCOVERY
      this->ip_mdns_.note_ipv6_status(node, current ? snapshot : ::mesh_ip::Ipv6AddressSnapshot{});
#endif
      // A pending DAD status is not a newer revocation. Only positive,
      // bounded grants renew the client's lease; stale negatives cannot undo
      // a later ready grant with the same client revision.
      if (current && snapshot.ready)
        send(node, CONTROL_IPV6_GRANT, snapshot, true);
    }
  }
  if (this->ip_gateway_ != 0 && this->node_id_ != this->ip_gateway_) {
    ::mesh_ip::Ipv6AddressSnapshot snapshot;
    if (this->ip_netif_.local_ipv6_claim(snapshot) && snapshot.generation != 0)
      send(this->ip_gateway_, CONTROL_IPV6_CLAIM, snapshot, !direct);
  }
}
#endif

#ifdef USE_MESH_DISCOVERY
void MeshComponent::discovery_loop_() {
  // ESP-IDF delegated registration can wait for the mDNS task. Keep it outside
  // the transport mutex so TCP/OTA and authenticated mesh heartbeats continue.
  bool gateway;
  {
    MeshGuard guard(this->mutex_);
    gateway = this->gateway_service_() && this->last_direct_uplink_;
  }
  this->ip_mdns_.loop(this->ip_netif_, gateway);
#ifndef MESH_IP_GATEWAY_ONLY
  {
    MeshGuard guard(this->mutex_);
    if (this->node_id_ == this->ip_gateway_ || this->discovery_length_ != 0)
      return;
  }
  uint8_t descriptor[::mesh_ip::DISCOVERY_DESCRIPTOR_MAX];
  size_t length;
  if (this->ip_mdns_.local_descriptor(descriptor, sizeof(descriptor), length)) {
    MeshGuard guard(this->mutex_);
    std::memcpy(this->discovery_descriptor_, descriptor, length);
    this->discovery_length_ = length;
  }
#endif
}

void MeshComponent::discovery_tick_(uint32_t now, bool associated) {
#ifdef MESH_IP_GATEWAY_ONLY
  (void) now;
  (void) associated;
#else
  const bool active = this->ip_gateway_ != 0 && this->node_id_ != this->ip_gateway_ && !associated &&
                      !this->ip_handover_.quiet() && this->ip_netif_.available() && this->ip_netif_.fallback_active();
  if (active && !this->discovery_was_active_) {
    this->last_discovery_ = now - 5000;
    this->last_discovery_metadata_check_ = now - 500;
  }
  this->discovery_was_active_ = active;
  if (!active) {
    this->discovery_offset_ = 0;
    for (auto &offset : this->discovery_gateway_offsets_)
      offset = 0;
    return;
  }
#ifdef MESH_IPV6
  if (!this->ip_netif_.ipv4_available()) {
    ::mesh_ip::Ipv6AddressSnapshot snapshot;
    if (!this->ip_netif_.local_ipv6_snapshot(snapshot) || !snapshot.ready || snapshot.count == 0 ||
        this->discovery_length_ == 0)
      return;
    if (snapshot.generation != this->ipv6_discovery_generation_) {
      this->ipv6_discovery_generation_ = snapshot.generation;
      this->ipv6_discovery_offset_ = 0;
      this->last_ipv6_discovery_ = now - 5000;
    }
    if (this->ipv6_discovery_offset_ == 0 && uint32_t(now - this->last_ipv6_discovery_) < 5000)
      return;
    ::mesh_ip::Ipv6Address address = snapshot.addresses[0];
    for (size_t i = 0; i < snapshot.count; ++i)
      if (!snapshot.addresses[i].link_local()) {
        address = snapshot.addresses[i];
        break;
      }
    // Keep valid deprecated addresses for existing sockets, but advertise a
    // preferred non-link-local address for new connections when available.
    for (size_t i = 0; i < snapshot.count; ++i)
      if ((snapshot.preferred_mask & (uint8_t(1) << i)) != 0 && !snapshot.addresses[i].link_local()) {
        address = snapshot.addresses[i];
        break;
      }
    uint8_t chunk[::mesh_ip::DISCOVERY_FRAME_MAX];
    size_t length;
    if (this->transport_has_room_() &&
        ::mesh_ip::discovery_chunk(this->discovery_descriptor_, this->discovery_length_, address,
                                   this->ipv6_discovery_offset_, chunk, sizeof(chunk), length,
                                   this->transport_payload_mtu_()) &&
        this->core_->send_control(this->ip_gateway_, ++this->sequence_, chunk, length, now)) {
      this->ipv6_discovery_offset_ += length - ::mesh_ip::DISCOVERY_IPV6_HEADER_SIZE;
      if (this->ipv6_discovery_offset_ >= this->discovery_length_) {
        this->ipv6_discovery_offset_ = 0;
        this->last_ipv6_discovery_ = now;
      }
    }
    return;
  }
#endif
  if (this->ip_gateways_ != 0) {
    if (this->discovery_length_ == 0)
      return;
    const uint32_t address = this->ip_netif_.address();
    // Descriptors are normally immutable for one boot. Still invalidate a
    // partial transfer if its local metadata or lease address changes. Hash
    // checks are bounded instead of repeating the CRC every worker iteration.
    if (uint32_t(now - this->last_discovery_metadata_check_) >= 500 || address != this->discovery_metadata_address_ ||
        this->discovery_length_ != this->discovery_metadata_length_) {
      this->last_discovery_metadata_check_ = now;
      const uint32_t digest = ::mesh_ip::discovery_digest(this->discovery_descriptor_, this->discovery_length_);
      if (digest != this->discovery_metadata_digest_ || address != this->discovery_metadata_address_ ||
          this->discovery_length_ != this->discovery_metadata_length_) {
        this->discovery_metadata_digest_ = digest;
        this->discovery_metadata_address_ = address;
        this->discovery_metadata_length_ = this->discovery_length_;
        this->last_discovery_ = now - 5000;
      }
    }
    if (uint32_t(now - this->last_discovery_) >= 5000) {
      this->last_discovery_ = now;
      for (size_t i = 0; i < mesh_limits::MAX_NODES; i++) {
        this->discovery_gateway_offsets_[i] = 0;
        this->discovery_gateway_attempts_[i] = now - 500;
      }
    }
    for (uint8_t gateway = 1; gateway <= mesh_limits::MAX_NODES; gateway++) {
      if (gateway == this->node_id_ || !this->gateway_candidate_(gateway))
        continue;
      auto &offset = this->discovery_gateway_offsets_[gateway - 1];
      auto &attempt = this->discovery_gateway_attempts_[gateway - 1];
      if (offset >= this->discovery_length_ || uint32_t(now - attempt) < 500)
        continue;
      if (!this->transport_has_room_())
        break;
      uint8_t chunk[::mesh_ip::DISCOVERY_FRAME_MAX];
      size_t length;
      if (!::mesh_ip::discovery_chunk(this->discovery_descriptor_, this->discovery_length_, address, offset, chunk,
                                      sizeof(chunk), length, this->transport_payload_mtu_()))
        continue;
      if (this->core_->send_control(gateway, ++this->sequence_, chunk, length, now)) {
        offset += length - ::mesh_ip::DISCOVERY_HEADER_SIZE;
        attempt = now - 500;
      } else {
        // A partial descriptor has a two-second assembly budget remotely.
        // Restart this edge after bounded backpressure without resending any
        // successful edge's already completed descriptor every worker loop.
        offset = 0;
        attempt = now;
      }
    }
    return;
  }
  if (this->discovery_length_ == 0 || (this->discovery_offset_ == 0 && uint32_t(now - this->last_discovery_) < 5000) ||
      !this->transport_has_room_())
    return;
  uint8_t chunk[::mesh_ip::DISCOVERY_FRAME_MAX];
  size_t length;
  bool accepted = false;
  if (::mesh_ip::discovery_chunk(this->discovery_descriptor_, this->discovery_length_, this->ip_netif_.address(),
                                 this->discovery_offset_, chunk, sizeof(chunk), length,
                                 this->transport_payload_mtu_())) {
    accepted = this->core_->send_control(this->ip_gateway_, ++this->sequence_, chunk, length, now);
  }
  if (accepted) {
    this->discovery_offset_ += length - ::mesh_ip::DISCOVERY_HEADER_SIZE;
    if (this->discovery_offset_ >= this->discovery_length_) {
      this->discovery_offset_ = 0;
      this->last_discovery_ = now;
    }
  }
#endif
}
#endif

void MeshComponent::ip_deliver_(const ::mesh_core::Frame &frame) {
  // Candidate mode accepts reverse traffic from every configured LAN edge;
  // the legacy mode accepts only its fixed gateway. Apply the origin policy
  // before allocating a reassembly slot. Transit packets stay in MeshCore.
  const bool from_gateway =
      this->ip_gateways_ != 0 ? this->gateway_candidate_(frame.source) : frame.source == this->ip_gateway_;
  if ((!this->gateway_service_() || !this->last_direct_uplink_) && !from_gateway) {
    this->ip_reassembly_drops_++;
    return;
  }
  const auto result = this->ip_delivery_.receive_fragment(frame.source, frame.destination, frame.payload,
                                                          frame.payload_length, millis());
  if (result == ::mesh_ip::ReceiveResult::INVALID)
    this->ip_reassembly_drops_++;
}

bool MeshComponent::ip_send_fragment_(void *context, uint8_t destination, const uint8_t *packet, size_t length) {
  auto *self = static_cast<MeshComponent *>(context);
  return self->transport_has_room_() &&
         self->core_->send_data(destination, ++self->sequence_, packet, length, millis());
}

bool MeshComponent::ip_send_ack_(void *context, uint8_t destination, const uint8_t *packet, size_t length) {
  if (length != ::mesh_ip::kDeliveryAckSize)
    return false;
  auto *self = static_cast<MeshComponent *>(context);
  uint8_t control[::mesh_ip::kDeliveryAckSize + 2]{CONTROL_VERSION, CONTROL_IP_ACK};
  std::memcpy(control + 2, packet, length);
  return self->core_->send_control(destination, ++self->sequence_, control, sizeof(control), millis());
}

bool MeshComponent::ip_accept_packet_(void *context, uint8_t source, const uint8_t *packet, size_t length) {
  return static_cast<MeshComponent *>(context)->ip_accept_(source, packet, length);
}

bool MeshComponent::ip_accept_(uint8_t source, const uint8_t *packet, size_t length) {
  const bool from_gateway = this->ip_gateways_ != 0 ? this->gateway_candidate_(source) : source == this->ip_gateway_;
  if (!this->last_direct_uplink_ &&
      (this->mesh_radio_active_ || (this->ip_gateways_ != 0 && this->wifi_fault_active_)) && from_gateway) {
    const auto dhcp = this->dhcp_client_.receive(packet, length, millis());
    if (dhcp != ::mesh_ip::DhcpResult::IGNORED) {
      if (dhcp == ::mesh_ip::DhcpResult::LEASE_BOUND) {
        if (this->ip_handover_.quiet())
          return true;
        const auto &lease = this->dhcp_client_.lease();
        if (this->dhcp_lease_installed_ && this->ip_netif_.address() == lwip_htonl(lease.address))
          this->accept_mesh_lease_();
        else
          this->begin_dhcp_probe_(millis());
      } else if (dhcp == ::mesh_ip::DhcpResult::LEASE_REJECTED) {
        this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
        this->dhcp_quiet_.cancel();
        this->ip_netif_.clear_mesh_lease();
        ESP_LOGW(TAG, "IP_LEASE NAK: withdraw address and restart DHCP");
      }
      return true;
    }
  }
  return this->ip_netif_.deliver_mesh(source, packet, length);
}

void MeshComponent::begin_dhcp_probe_(uint32_t now) {
  this->dhcp_lease_installed_ = false;
  this->dhcp_probe_pending_ = true;
  this->last_dhcp_probe_ = now - 500;
  this->ip_netif_.clear_mesh_lease();
  this->dhcp_quiet_.cancel();
  if (this->ip_gateways_ != 0) {
    uint32_t nonce = esp_random();
    if (nonce == this->ip_handover_.nonce())
      nonce ^= 0x80000000U;
    const uint16_t expected = this->known_gateway_mask_() & ~uint16_t(1U << (this->node_id_ - 1));
    this->dhcp_quiet_.begin(now, nonce, expected);
  }
  ESP_LOGI(TAG, "IP_LEASE offered: withdraw old proxy grants before gateway ARP conflict check");
}

void MeshComponent::accept_mesh_lease_() {
  const auto &lease = this->dhcp_client_.lease();
  if (!this->ip_netif_.install_valid_lease(lwip_htonl(lease.address), lwip_htonl(lease.netmask),
                                           lwip_htonl(lease.router))) {
    // A TCP/IP role change may still be queued. Keep requesting the correlated
    // probe result instead of stranding a BOUND client until its normal T1.
    this->dhcp_probe_pending_ = true;
    this->last_dhcp_probe_ = millis() - 500;
    return;
  }
  this->dhcp_lease_installed_ = true;
  this->dhcp_probe_pending_ = false;
  this->dhcp_quiet_.cancel();
  if (lease.dns != 0) {
    this->mesh_dns_.store(lease.dns);
    tcpip_try_callback(set_mesh_dns_, this);
  }
  ip4_addr_t address{lwip_htonl(lease.address)}, server{lwip_htonl(lease.server)};
  // ip4addr_ntoa uses one shared buffer, so copy each result before logging.
  char text[16], server_text[16];
  ip4addr_ntoa_r(&address, text, sizeof(text));
  ip4addr_ntoa_r(&server, server_text, sizeof(server_text));
  ESP_LOGI(TAG, "IP_LEASE acquired address=%s lease=%u server=%s", text, static_cast<unsigned>(lease.lifetime_seconds),
           server_text);
  this->last_ip_status_ = millis() - 500;
}

void MeshComponent::set_mesh_dns_(void *context) {
  const uint32_t value = static_cast<MeshComponent *>(context)->mesh_dns_.load();
  ip_addr_t dns{};
  IP_ADDR4(&dns, (value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255);
  dns_setserver(0, &dns);
}

void MeshComponent::dhcp_tick_(uint32_t now, bool direct) {
#ifdef MESH_HAS_ETHERNET
  if (direct)
    return;
#endif
  if (!this->mesh_radio_active_ && !(this->ip_gateways_ != 0 && this->wifi_fault_active_))
    return;
  this->dhcp_client_.tick(now);
  // Address lifetime is an endpoint property even while no route exists.
  if (!this->dhcp_client_.lease_valid(now) && (this->dhcp_lease_installed_ || this->dhcp_probe_pending_)) {
    this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
    this->dhcp_quiet_.cancel();
    this->ip_netif_.clear_mesh_lease();
    ESP_LOGW(TAG, "IP_LEASE expired: withdraw address until DHCP succeeds");
  }
  if (this->ip_gateway_ == 0 || this->node_id_ == this->ip_gateway_ || direct || this->ip_handover_.quiet())
    return;
  if (this->gateway_revalidate_) {
    if (this->dhcp_client_.state() != ::mesh_ip::DhcpState::STOPPED ||
        this->dhcp_client_.configure(this->own_mac_.data())) {
      this->dhcp_client_.force_revalidate(esp_random(), now);
      this->gateway_revalidate_ = false;
      ESP_LOGI(TAG, "IP_LEASE renewal for gateway=%u: missing initial/warm witness", this->ip_gateway_);
      if (this->dhcp_client_.state() == ::mesh_ip::DhcpState::SELECTING)
        ESP_LOGI(TAG, "IP_LEASE discover: no previous address, requesting DHCP through mesh");
    }
  }
  if (this->gateway_revalidate_)
    return;
  if (this->dhcp_client_.state() == ::mesh_ip::DhcpState::STOPPED &&
      this->dhcp_client_.configure(this->own_mac_.data())) {
    this->dhcp_client_.start(esp_random(), now);
    ESP_LOGI(TAG, "IP_LEASE discover: no previous address, requesting DHCP through mesh");
  }
  this->dhcp_client_.tick(now);
  if (this->dhcp_probe_pending_ && (this->ip_gateways_ == 0 || this->dhcp_quiet_.ready(now)) &&
      now - this->last_dhcp_probe_ >= 500) {
    this->last_dhcp_probe_ = now;
    uint8_t request[10]{CONTROL_VERSION, CONTROL_LEASE_PROBE};
    const uint32_t nonce = this->dhcp_client_.xid(), address = lwip_htonl(this->dhcp_client_.lease().address);
    for (size_t i = 0; i < 4; i++)
      request[2 + i] = (nonce >> (8 * i)) & 0xff;
    std::memcpy(request + 6, &address, 4);
    this->core_->send_control(this->ip_gateway_, ++this->sequence_, request, sizeof(request), now);
  }
  if (this->core_->route().connected && this->ip_delivery_.can_begin() && this->transport_has_room_()) {
    ::mesh_ip::MeshIpNetif::IpPacket packet;
    size_t length = 0;
    if (this->dhcp_client_.poll(now, packet.data, sizeof(packet.data), length)) {
      this->ip_delivery_.begin(this->ip_gateway_, packet.data, length, ++this->ip_packet_sequence_, now);
    }
  }
}

bool MeshComponent::send_probe(uint8_t destination) {
  MeshGuard guard(this->mutex_);
  return this->send_probe_(destination, 0);
}

bool MeshComponent::send_probe_(uint8_t destination, uint32_t run) {
  if (!this->core_ || !this->allowed_(destination) || destination == this->node_id_)
    return false;
  const uint16_t sequence = ++this->sequence_;
  if (run != 0) {
    ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=send seq=%u peer=%u",
             static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(run), sequence,
             destination);
  }
  PendingProbe *slot = nullptr;
  for (auto &pending : this->pending_probes_) {
    if (!pending.used) {
      slot = &pending;
      break;
    }
  }
  if (slot == nullptr) {
    if (run != 0) {
      ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=overflow seq=%u peer=%u",
               static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(run), sequence,
               destination);
    }
    return false;
  }
  const uint32_t sent_ms = millis();
  const uint32_t sent_us = micros();
  bool sent;
  if (run != 0) {
    uint8_t payload[BENCHMARK_PAYLOAD_SIZE];
    for (size_t i = 0; i < BENCHMARK_PAYLOAD_SIZE; i++)
      payload[i] = static_cast<uint8_t>(i);
    sent = this->core_->send_probe_payload(destination, sequence, payload, sizeof(payload), sent_ms);
  } else {
    sent = this->core_->send_probe(destination, sequence, sent_ms);
  }
  if (sent) {
    *slot = PendingProbe{true, destination, sequence, sent_ms, sent_us, run};
  } else if (run != 0) {
    ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=unroutable seq=%u peer=%u",
             static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(run), sequence,
             destination);
  }
  ESP_LOGI(TAG, "PROBE_SEND from=%u to=%u seq=%u queued=%s", this->node_id_, destination, sequence, YESNO(sent));
  return sent;
}

bool MeshComponent::start_probe_benchmark(uint8_t destination, uint16_t count, uint32_t interval_ms) {
  MeshGuard guard(this->mutex_);
  if (!this->core_ || this->benchmark_active_ || !this->allowed_(destination) || destination == this->node_id_ ||
      count == 0 || count > 10000 || interval_ms < 100 || interval_ms > 60000)
    return false;
  if (++this->benchmark_run_ == 0)
    ++this->benchmark_run_;
  this->benchmark_peer_ = destination;
  this->benchmark_count_ = count;
  this->benchmark_sent_ = 0;
  this->benchmark_interval_ = interval_ms;
  this->benchmark_last_send_ = millis() - interval_ms;
  this->benchmark_active_ = true;
  ESP_LOGI(TAG,
           "BENCH boot=%08X node=%u run=%u kind=start peer=%u count=%u interval_ms=%u timeout_ms=%u payload_bytes=%u",
           static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(this->benchmark_run_),
           destination, count, static_cast<unsigned>(interval_ms), static_cast<unsigned>(PROBE_TIMEOUT_MS),
           static_cast<unsigned>(BENCHMARK_PAYLOAD_SIZE));
  return true;
}

void MeshComponent::stop_probe_benchmark() {
  MeshGuard guard(this->mutex_);
  if (!this->benchmark_active_)
    return;
  ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=cancel sent=%u", static_cast<unsigned>(this->benchmark_boot_),
           this->node_id_, static_cast<unsigned>(this->benchmark_run_), this->benchmark_sent_);
  this->benchmark_active_ = false;
}

void MeshComponent::benchmark_tick_(uint32_t now) {
  bool waiting = false;
  for (auto &pending : this->pending_probes_) {
    if (!pending.used)
      continue;
    if (micros() - pending.sent_us >= PROBE_TIMEOUT_MS * 1000U) {
      if (pending.run != 0) {
        ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=timeout seq=%u peer=%u timeout_ms=%u",
                 static_cast<unsigned>(this->benchmark_boot_), this->node_id_, static_cast<unsigned>(pending.run),
                 pending.sequence, pending.peer, static_cast<unsigned>(PROBE_TIMEOUT_MS));
      }
      pending.used = false;
    } else if (pending.run == this->benchmark_run_) {
      waiting = true;
    }
  }
  if (!this->benchmark_active_)
    return;
  if (this->benchmark_sent_ == this->benchmark_count_) {
    if (!waiting) {
      ESP_LOGI(TAG, "BENCH boot=%08X node=%u run=%u kind=finish sent=%u", static_cast<unsigned>(this->benchmark_boot_),
               this->node_id_, static_cast<unsigned>(this->benchmark_run_), this->benchmark_sent_);
      this->benchmark_active_ = false;
    }
    return;
  }
  if (now - this->benchmark_last_send_ >= this->benchmark_interval_) {
    this->benchmark_last_send_ = now;
    this->send_probe_(this->benchmark_peer_, this->benchmark_run_);
    this->benchmark_sent_++;
  }
}

bool MeshComponent::send_control_(uint8_t destination, uint8_t command, uint32_t duration_ms) {
  if (!this->core_ || !this->allowed_(destination))
    return false;
  uint8_t payload[6]{CONTROL_VERSION, command};
  for (size_t i = 0; i < 4; i++)
    payload[2 + i] = (duration_ms >> (8 * i)) & 0xFF;
  const uint16_t sequence = ++this->sequence_;
  const bool sent = this->core_->send_control(destination, sequence, payload, sizeof(payload), millis());
  ESP_LOGI(TAG, "CONTROL_SEND to=%u seq=%u command=%u queued=%s", destination, sequence, command, YESNO(sent));
  return sent;
}

bool MeshComponent::send_wifi_fault(uint8_t destination, uint32_t duration_ms) {
  MeshGuard guard(this->mutex_);
  if (duration_ms < 1000 || duration_ms > 600000) {
    ESP_LOGW(TAG, "Fault duration must be 1000..600000 ms");
    return false;
  }
  return this->send_control_(destination, CONTROL_WIFI_FAULT, duration_ms);
}

bool MeshComponent::send_wifi_recover(uint8_t destination) {
  MeshGuard guard(this->mutex_);
  return this->send_control_(destination, CONTROL_WIFI_RECOVER, 0);
}

bool MeshComponent::start_unassociated_radio_() {
  this->last_radio_start_ = millis();
  this->radio_start_pending_ = true;
  Esp32WifiPlatform::ChannelBounds bounds;
  if (!Esp32WifiPlatform::start_unassociated(this->cached_channel_, bounds))
    return false;
  this->channel_search_.set_country(bounds.first, bounds.count);
  this->native_recovery_.set_country(bounds.first, bounds.count);
  if (!Esp32WifiPlatform::station_address(this->own_mac_))
    return false;
  this->radio_start_pending_ = false;
  this->transport_.set_sdk_enabled(true);
  return this->runtime_->start();
}

::mesh_radio::RadioTxState MeshComponent::capture_radio_state_(bool diagnostic) const {
  // ESPHome already caches these flags. An association read cannot permit
  // mesh traffic before native IP is ready, so avoid polling the driver during
  // acquisition except for the infrequent, actual-state diagnostic sample.
  const auto native = Esp32WifiPlatform::native_state();
  const bool connected = native.connected;
  const bool roaming = native.roaming;
  const bool associated = (connected || diagnostic) && Esp32WifiPlatform::associated();
  return {this->mesh_radio_active_ || this->wifi_fault_active_,
          associated,
          connected,
          roaming,
          this->wifi_scan_active_,
          this->channel_hop_pending_};
}

void MeshComponent::update_roaming_suppression_(bool needed) {
  // Only the worker owns this scoped request. Shutdown publishes its existing
  // atomic flag; the next tick or worker exit releases without a hook mutex.
  if (needed && !this->roaming_suppression_held_)
    this->roaming_suppression_held_ = Esp32WifiPlatform::request_roaming_suppression();
  else if (!needed && this->roaming_suppression_held_) {
    Esp32WifiPlatform::release_roaming_suppression();
    this->roaming_suppression_held_ = false;
  }
}

void MeshComponent::update_radio_lifecycle_(const ::mesh_radio::RadioTxState &state) {
  const bool allowed = !this->native_recover_pending_ && this->pending_command_ != CONTROL_WIFI_FAULT &&
                       !this->radio_start_pending_ && ::mesh_radio::RadioOwnership::lifecycle_allowed(state);
  this->transport_.set_sdk_enabled(allowed);
}

bool MeshComponent::radio_tx_allowed_(const ::mesh_radio::RadioTxState &state) const {
  return this->transport_.sdk_enabled() && !this->native_recover_pending_ && !this->radio_start_pending_ &&
         ::mesh_radio::RadioOwnership::transmit_allowed(state);
}

uint8_t MeshComponent::refresh_radio_channel_(bool direct, bool roaming, bool sample) {
  if (!sample)
    return 0;
  uint8_t primary = 0;
  Esp32WifiPlatform::current_channel(primary);
  // A connected roam can change channels without a direct-route edge. The
  // periodic diagnostic refreshes that cache, never from off-channel scans.
  if (direct && !roaming && primary != 0)
    this->cached_channel_ = primary;
  return primary;
}

void MeshComponent::maybe_search_channel_() {
  uint8_t target = 0;
  bool was_searching = false;
  {
    MeshGuard guard(this->mutex_);
    if (this->native_recover_pending_) {
      this->channel_hop_pending_ = false;
      return;
    }
    if (!this->core_ || this->channel_switch_active_)
      return;
    if (!this->mesh_radio_active_ && !this->wifi_fault_active_) {
      this->channel_search_.candidate(millis(), this->cached_channel_, {});
      this->channel_hop_pending_ = false;
      return;
    }
    const auto &route = this->core_->route();
    ::mesh_radio::RadioSearchState state;
    state.mesh_owned = this->mesh_radio_active_ || this->wifi_fault_active_;
    state.wifi_disabled = Esp32WifiPlatform::disabled();
    state.associated = Esp32WifiPlatform::associated();
    state.quiet = this->ip_handover_.quiet();
    state.scanning = this->wifi_scan_active_;
    state.route_connected = route.connected;
    state.route_root = route.root;
    // A disconnected dynamic node still needs to search for any candidate.
    state.gateway = this->ip_gateways_ != 0 && this->ip_gateway_ == 0 ? 255 : this->ip_gateway_;
    was_searching = this->channel_search_.searching();
    target = this->channel_search_.candidate(millis(), this->cached_channel_, state);
    if (was_searching && !this->channel_search_.searching() && state.mesh_owned && route.connected)
      ESP_LOGI(TAG, "RADIO_SEARCH locked channel=%u root=%u parent=%u", this->cached_channel_, route.root,
               route.parent);
    if (!was_searching && this->channel_search_.searching())
      ESP_LOGI(TAG, "RADIO_SEARCH begin channel=%u dwell=%u ms", this->cached_channel_,
               static_cast<unsigned>(::mesh_radio::ChannelSearch::DWELL_MS));
    this->channel_hop_pending_ = target != 0;
    if (target == 0 || this->runtime_->queue_state().inflight)
      return;
    // Eligibility was checked again after any previous wait for the callback.
    // Reserving the PHY also prevents a new authenticated route appearing in
    // the worker between that decision and the SDK call below.
    this->channel_switch_active_ = true;
  }

  const bool switched = Esp32WifiPlatform::switch_channel(target);

  {
    MeshGuard guard(this->mutex_);
    this->channel_search_.complete(millis(), target, switched);
    if (switched) {
      this->cached_channel_ = target;
      // No send is in flight. Old-channel packets are obsolete, but preserve
      // DHCP, metadata ownership, authenticated peer keys and core sequences.
      this->runtime_->cancel_pending(false);
      this->runtime_->discard_receive();
      ESP_LOGD(TAG, "RADIO_SEARCH channel=%u", target);
    } else {
      ESP_LOGW(TAG, "RADIO_SEARCH channel=%u rejected", target);
    }
    this->channel_hop_pending_ = false;
    this->channel_switch_active_ = false;
  }
}

void MeshComponent::enter_mesh_radio_() {
  if (this->mesh_radio_active_)
    return;
  // The acquisition deadline remains due if the SDK cannot yet relinquish
  // ownership. A later loop pass retries without changing the shared PHY.
  if (!this->transport_.set_sdk_enabled(false))
    return;
  this->runtime_->stop();
  Esp32WifiPlatform::pause_native();
  this->cached_channel_ = this->radio_ownership_.preferred_mesh_channel(millis(), this->cached_channel_);
  this->mesh_radio_active_ = true;
  this->radio_start_pending_ = true;
  this->last_radio_start_ = millis();
  this->last_wifi_probe_ = millis();
  this->ip_handover_.cancel();
  if (!this->native_handover_attempt_ || !this->dhcp_client_.lease_valid(millis()))
    this->dhcp_client_.stop();
  else
    this->gateway_revalidate_ = true;
  this->native_handover_attempt_ = false;
  this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
  this->dhcp_quiet_.cancel();
  this->ip_netif_.clear_mesh_lease();
  ESP_LOGI(TAG, "MESH_RADIO active=YES reason=native_unavailable");
  this->start_unassociated_radio_();
}

void MeshComponent::maybe_probe_wifi_() {
  uint8_t scan_channel = 0;
  uint8_t home_channel = 0;
  {
    MeshGuard guard(this->mutex_);
    const bool requested = Esp32WifiPlatform::native_requested();
    if (requested && !this->last_native_requested_) {
      this->last_wifi_probe_ = millis() - ::mesh_radio::NativeRecovery::ROUND_MS;
      this->native_recovery_.cancel();
    }
    this->last_native_requested_ = requested;
    if (this->native_recover_pending_ || !this->mesh_radio_active_ || this->native_wifi_networks_.empty() ||
        (!requested && !this->wifi_restore_pending_)) {
      this->wifi_scan_active_ = false;
      this->wifi_restore_pending_ = false;
      this->wifi_probe_found_ = false;
      this->native_recovery_.cancel();
      if (!this->native_recover_pending_)
        this->native_wifi_candidate_ = {};
      return;
    }
    if (!requested) {
      this->wifi_probe_found_ = false;
      this->native_wifi_candidate_ = {};
      this->native_recovery_.cancel();
    }
    if (this->channel_switch_active_)
      return;
    const uint32_t now = millis();
    if (this->wifi_restore_pending_) {
      if (now - this->last_wifi_restore_ < ::mesh_radio::NativeRecovery::STEP_MS)
        return;
      home_channel = this->wifi_scan_home_;
    } else {
      if (!this->wifi_scan_active_ && !this->native_recovery_.due(now, this->last_wifi_probe_))
        return;
      // Reserve TX first, then drain its single SDK callback before scanning.
      // The worker still services callbacks while this reservation is held.
      this->wifi_scan_active_ = true;
      if (this->runtime_->queue_state().inflight)
        return;
      scan_channel = this->native_recovery_.next(now, this->cached_channel_, this->last_wifi_probe_);
      if (scan_channel == 0) {
        this->wifi_scan_active_ = false;
        return;
      }
      home_channel = this->cached_channel_;
      this->wifi_scan_home_ = home_channel;
    }
    this->channel_switch_active_ = true;
  }
  bool found = false;
  bool scanned = false;
  ::mesh_radio::NativeWifiCandidate candidate;
  if (scan_channel != 0)
    scanned = Esp32WifiPlatform::probe_native_ap(this->native_wifi_networks_.data(), this->native_wifi_networks_.size(),
                                                 scan_channel, found, &candidate);
  // Do not rely on SDK scan completion restoring the home channel. No sender
  // may resume, nor native handover begin, until the restore is acknowledged.
  const bool restored = Esp32WifiPlatform::switch_channel(home_channel);
  MeshGuard guard(this->mutex_);
  this->channel_switch_active_ = false;
  if (scan_channel != 0) {
    this->native_recovery_.complete(millis(), scan_channel);
    this->wifi_probe_found_ = scanned && found;
    this->native_wifi_candidate_ = this->wifi_probe_found_ ? candidate : ::mesh_radio::NativeWifiCandidate{};
  }
  this->wifi_restore_pending_ = !restored;
  if (!restored) {
    this->last_wifi_restore_ = millis();
    return;
  }
  this->wifi_scan_active_ = false;
  if (this->wifi_probe_found_) {
    this->native_recovery_.cancel();
    this->wifi_probe_found_ = false;
    if (!this->ip_handover_.quiet()) {
      ESP_LOGI(TAG, "MESH_RADIO configured Wi-Fi AP available; begin address handover");
      if (this->mesh_ownership_address_(millis()) != 0)
        this->begin_ip_handover_();
      else
        this->finish_wifi_recover_();
    }
  }
}

void MeshComponent::start_wifi_fault(uint32_t duration_ms) {
  MeshGuard guard(this->mutex_);
  if (this->channel_switch_active_ || this->native_recover_pending_) {
    this->pending_command_ = CONTROL_WIFI_FAULT;
    this->pending_duration_ = duration_ms;
    return;
  }
  if (this->mesh_radio_active_)
    return;
  if (!this->core_) {
    ESP_LOGW(TAG, "Mesh is not ready; cannot start fault yet");
    return;
  }
  if (duration_ms < 1000 || duration_ms > 600000) {
    ESP_LOGW(TAG, "Fault duration must be 1000..600000 ms");
    return;
  }
  if (this->wifi_fault_active_) {
    this->wifi_fault_started_ = millis();
    this->wifi_fault_duration_ = duration_ms;
    this->ip_handover_.cancel();
    ESP_LOGI(TAG, "FAULT timer replaced: %u ms", static_cast<unsigned>(duration_ms));
    return;
  }
  if (!this->transport_.set_sdk_enabled(false)) {
    this->pending_command_ = CONTROL_WIFI_FAULT;
    this->pending_duration_ = duration_ms;
    return;
  }
  this->wifi_fault_started_ = millis();
  this->wifi_fault_duration_ = duration_ms;
  this->ip_handover_.cancel();
  uint8_t primary = 0;
  if (Esp32WifiPlatform::associated() && Esp32WifiPlatform::current_channel(primary))
    this->cached_channel_ = primary;
  this->wifi_fault_active_ = true;
  if (!Esp32LanPlatform::ethernet_connected())
    this->core_->set_direct_uplink(false, millis());
  this->runtime_->stop();
  // ESPHome disable suppresses its reconnect state machine and stops the driver.
  // This is a real association fault with a short radio reset at each boundary.
  Esp32WifiPlatform::pause_native();
  ESP_LOGW(TAG, "FAULT begin: real STA disconnect, reconnect suppressed for %u ms; restart ESP-NOW PHY on channel %u",
           static_cast<unsigned>(duration_ms), this->cached_channel_);
  this->start_unassociated_radio_();
}

void MeshComponent::clear_wifi_fault() {
  MeshGuard guard(this->mutex_);
  if (this->channel_switch_active_ || this->wifi_restore_pending_) {
    this->pending_command_ = CONTROL_WIFI_RECOVER;
    return;
  }
  if (!Esp32WifiPlatform::native_requested() || (!this->wifi_fault_active_ && !this->mesh_radio_active_))
    return;
  // Repeated recovery requests must keep the captured ownership barrier even
  // after taking over initial DAD removed its pending lease/alias markers.
  // The main loop alone advances a ready handover into Wi-Fi association.
  if (this->ip_handover_.quiet())
    return;
  if (this->mesh_ownership_address_(millis()) != 0) {
    if (!this->ip_handover_.waiting())
      this->begin_ip_handover_();
    return;
  }
  this->finish_wifi_recover_();
}

uint32_t MeshComponent::mesh_ownership_address_(uint32_t now) const {
  if (Esp32LanPlatform::ethernet_connected())
    return 0;  // Ethernet's own lease is not an address held by a mesh proxy.
  if (this->ip_gateways_ == 0 && (this->ip_gateway_ == 0 || this->node_id_ == this->ip_gateway_))
    return 0;
  const uint32_t address = this->ip_netif_.address();
  if (address != 0)
    return address;
  if (this->ip_gateways_ != 0 && this->dhcp_probe_pending_ && this->dhcp_client_.lease_valid(now))
    return lwip_htonl(this->dhcp_client_.lease().address);
  return 0;
}

void MeshComponent::begin_ip_handover_() {
  const uint32_t now = millis();
  const uint16_t expected = this->known_gateway_mask_() & ~uint16_t(1U << (this->node_id_ - 1));
  this->ip_handover_address_ = this->mesh_ownership_address_(now);
  this->dhcp_quiet_.cancel();
  this->dhcp_probe_pending_ = false;
  this->ip_handover_.begin(now, esp_random(), expected);
  this->last_ip_status_ = now - 500;
  ESP_LOGI(TAG, "IP_HANDOVER begin: withdraw gateway proxy before DHCP; await ACK or peer lease expiry");
}

void MeshComponent::cancel_native_recovery_() {
  const bool transfer_started = this->native_recover_pending_ || !this->mesh_radio_active_;
  const bool withdrawn = this->ip_handover_.quiet();
  this->native_recover_pending_ = false;
  this->native_wifi_candidate_ = {};
  this->wifi_probe_found_ = false;
  this->native_recovery_.cancel();
  this->ip_handover_.cancel();
  if (withdrawn || transfer_started) {
    // A withdrawn grant is not reusable, even though its DHCP clock survives.
    this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
    this->dhcp_quiet_.cancel();
    this->ip_netif_.clear_mesh_lease();
    this->gateway_revalidate_ = true;
  }
  if (transfer_started) {
    this->mesh_radio_active_ = this->wifi_fault_active_ = false;
    this->native_handover_attempt_ = true;
    this->enter_mesh_radio_();
  } else if (this->wifi_fault_active_) {
    this->wifi_fault_active_ = false;
    this->mesh_radio_active_ = true;
  }
}

void MeshComponent::finish_wifi_recover_() {
  if (!this->wifi_fault_active_ && !this->mesh_radio_active_)
    return;
  if (!Esp32WifiPlatform::native_requested()) {
    this->cancel_native_recovery_();
    return;
  }
  // An SDK teardown failure does not transfer the shared PHY. Keep the IP
  // withdrawal barrier and retry from loop(), without blocking either task.
  this->native_recover_pending_ = true;
  if (!this->transport_.set_sdk_enabled(false))
    return;
  if (this->ip_handover_.quiet())
    ESP_LOGI(TAG, "IP_HANDOVER ready: gateway_ack=%s; keep proxy withdrawn through DHCP",
             YESNO(this->ip_handover_.acknowledged()));
  this->native_handover_attempt_ = this->native_handover_attempt_ || this->ip_netif_.fallback_active();
  if (this->mesh_radio_active_) {
    // Keep the lease clock for rollback; it is not permission to forward.
    // A failed native attempt returns through a fresh gateway revalidation.
    this->native_handover_attempt_ = true;
    this->dhcp_lease_installed_ = this->dhcp_probe_pending_ = false;
    this->dhcp_quiet_.cancel();
    this->ip_netif_.clear_mesh_lease();
  }
  // Match the ESPHome driver's cached stopped state before handing ownership back.
  if (!Esp32WifiPlatform::stop_radio())
    return;
  bool resumed;
  if (this->native_wifi_candidate_.valid(this->native_wifi_networks_.size())) {
    resumed = Esp32WifiPlatform::resume_native(this->native_wifi_networks_[this->native_wifi_candidate_.network_index],
                                               this->native_wifi_candidate_);
  } else {
    resumed = Esp32WifiPlatform::resume_native();
  }
  if (!resumed) {
    this->cancel_native_recovery_();
    return;
  }
  this->wifi_fault_active_ = false;
  this->mesh_radio_active_ = false;
  this->native_recover_pending_ = false;
  this->wifi_scan_active_ = false;
  this->radio_ownership_.start_native_acquisition(millis(), this->native_handover_attempt_);
  ESP_LOGW(TAG, "FAULT end: restore ESPHome Wi-Fi association; ESP-NOW waits for association");
  this->native_wifi_candidate_ = {};
}

void MeshComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "Capacity: nodes=%u radio_rx=%u radio_tx=%u ip_tx=%u ip_rx=%u",
                static_cast<unsigned>(mesh_limits::MAX_NODES), static_cast<unsigned>(EspNowTransport::RX_CAPACITY),
                static_cast<unsigned>(EspNowTransport::TX_CAPACITY),
                static_cast<unsigned>(::mesh_ip::IpFlowQueue::CAPACITY),
                static_cast<unsigned>(::mesh_ip::MeshIpNetif::receive_capacity()));
  ESP_LOGCONFIG(TAG, "ESP-NOW frame budget=%u, IP fragment data=%u",
                static_cast<unsigned>(EspNowTransport::NATIVE_FRAME_BUDGET),
                static_cast<unsigned>(::mesh_ip::kFragmentDataSize));
  MeshGuard guard(this->mutex_);
#ifdef USE_MESH_AUTO
  const ::mesh_protocol::Profile protocol;
#else
  const auto protocol = ::mesh_protocol::manual_profile();
#endif
#ifdef MESH_IPV6
  ESP_LOGCONFIG(TAG, "IPv6 proxy: authenticated capability required on all mesh peers; SLAAC /64, three addresses");
#endif
  ESP_LOGCONFIG(TAG, "Protocol: static_frame=%u session_frame=%u endpoint=%u payload=%u required=0x%04X",
                ::mesh_protocol::STATIC_FRAME_VERSION, protocol.frame_version, protocol.endpoint_revision,
                protocol.payload_budget, protocol.required);
  ESP_LOGCONFIG(TAG, "Mesh routing: node=%u, fallback channel=%u, encrypted peers=%u, max frame=%u bytes",
                this->node_id_, this->channel_, static_cast<unsigned>(this->transport_.peer_count()),
                static_cast<unsigned>(::mesh_core::kMaxWireSize));
  ESP_LOGCONFIG(TAG, "  IPv4 fallback: gateway=%u candidates=0x%04X, DHCP through gateway", this->ip_gateway_,
                this->ip_gateways_);
}

void MeshComponent::shutdown_tick_(uint32_t now) {
  if (!this->shutdown_requested_.load())
    return;
  if (!this->shutdown_handover_started_) {
    this->shutdown_handover_started_ = true;
    this->shutdown_handover_required_ = this->ip_gateway_ != 0 && this->node_id_ != this->ip_gateway_ &&
                                        this->ip_netif_.address() != 0 &&
                                        (this->wifi_fault_active_ || this->ip_netif_.fallback_active());
    if (this->shutdown_handover_required_)
      this->begin_ip_handover_();
  }
  if (!this->shutdown_handover_required_ || this->ip_handover_.ready(now))
    this->shutdown_handover_done_.store(true);
}

void MeshComponent::on_safe_shutdown() {
  // Start withdrawal before the remaining components run their safe hooks.
  this->shutdown_requested_.store(true);
}

void MeshComponent::on_shutdown() {
#ifdef USE_MESH_IP
  this->network_provider_.stop();
#endif
  if (!this->runtime_ || this->shutdown_hook_seen_)
    return;
  this->shutdown_hook_seen_ = true;
  this->shutdown_requested_.store(true);
  // Preserve the challenged proxy-withdrawal barrier before native DHCP can
  // restart. Its six-second bound exceeds the five-second forwarding grant.
  // Never acquire the worker mutex or enter the SDK from this hook: a stuck
  // worker must not prevent a reboot. Native mDNS owns responder destruction.
  const uint32_t started = millis();
  while (!this->shutdown_handover_done_.load() && !this->transport_exited_.load() &&
         uint32_t(millis() - started) < 6000) {
    App.feed_wdt();
    vTaskDelay(1);
  }
  if (!this->shutdown_handover_done_.load() && !this->transport_exited_.load())
    ESP_LOGW(TAG, "Shutdown handover deadline reached; stop worker");
  this->transport_stop_.store(true);
}

bool MeshComponent::teardown() {
  // ESPHome repeatedly calls this nonblocking hook with its overall deadline.
  // No synthetic success and no forced deletion of a task owning SDK buffers.
  return this->transport_exited_.load() && this->transport_.sdk_quiescent();
}

}  // namespace esphome::mesh
