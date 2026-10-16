#pragma once

#include "mesh_limits.h"

#include "esphome/core/component.h"
#include "mesh_core.h"
#include "mesh_runtime.h"
#include "mesh_management.h"
#include "mesh_esp32_platform.h"
#include "mesh_network_provider.h"
#include "mesh_ip_delivery.h"
#include "mesh_ip_netif.h"
#include "mesh_ip_handover.h"
#include "mesh_ip_dhcp.h"
#include "mesh_ip_mdns.h"
#include "mesh_endpoint.h"
#include "mesh_radio_channel.h"
#ifndef USE_MESH_AUTO
#include "mesh_session.h"
#endif
#include "mesh_radio_ownership.h"
#include "mesh_espnow_transport.h"
#ifdef USE_MESH_AUTO
#include "mesh_component_auto.h"
#endif

#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#ifndef MESH_NATIVE_WIFI_NETWORK_COUNT
#define MESH_NATIVE_WIFI_NETWORK_COUNT 0
#endif

namespace esphome::mesh {

class MeshComponent : public Component {
 public:
  static MeshComponent *get_instance() { return instance_; }
  void set_node_id(uint8_t value) { this->node_id_ = value; }
  void set_channel(uint8_t value) { this->channel_ = this->cached_channel_ = value; }
  void set_ip_gateway(uint8_t value) { this->ip_gateway_ = value; }
  void add_ip_gateway(uint8_t value) {
    if (!mesh_limits::valid_node(value))
      return;
    this->ip_gateways_ |= uint16_t(1U << (value - 1));
    if (this->ip_gateway_ == 0 || value < this->ip_gateway_)
      this->ip_gateway_ = value;
  }
  void set_route_stability(bool value) { this->route_stability_ = value; }
  uint8_t node_id() const;
  uint8_t first_peer_id() const;
#ifdef USE_MESH_AUTO
  void set_network_key(const std::array<uint8_t, 32> &value);
  void set_auto_pinned_id(bool value) { this->auto_->pinned = value; }
  void set_gateway_enabled(bool value) { this->auto_->gateway = value; }
  void add_auto_peer_restriction(uint8_t node, const std::array<uint8_t, 6> &mac);
  void add_auto_identity_restriction(uint8_t node, const std::array<uint8_t, 6> &mac);
#endif
  void set_native_wifi_network(size_t index, const char *ssid, const std::array<uint8_t, 6> &bssid, uint8_t channel,
                               bool has_bssid, bool hidden, bool requires_auth) {
    if (index < this->native_wifi_networks_.size())
      this->native_wifi_networks_[index] = {ssid, bssid, channel, has_bssid, hidden, requires_auth};
  }
  void add_ip_peer_mac(uint8_t node, const std::array<uint8_t, 6> &mac) {
#ifndef USE_MESH_AUTO
    if (mesh_limits::valid_node(node))
      this->manual_bindings_[node - 1].mac = mac;
#endif
    this->ip_netif_.set_dhcp_peer_mac(node, mac.data());
#ifdef USE_MESH_DISCOVERY
    this->ip_mdns_.authorize(node, mac.data());
#endif
  }
#ifdef USE_MESH_DISCOVERY
  void set_mdns_component(mdns::MDNSComponent *component) { this->ip_mdns_.set_component(component); }
#endif
  bool ip_enabled() const { return this->ip_gateways_ != 0 || this->ip_gateway_ != 0; }
  bool ip_available() const;
  bool ipv4_available() const;
#ifdef MESH_IPV6
  bool ipv6_snapshot(::mesh_ip::Ipv6AddressSnapshot &snapshot) const;
#endif
  uint32_t ip_address() const;
  void set_pmk(const std::array<uint8_t, 16> &value) { this->transport_.set_pmk(value); }
  void allow_node(uint8_t value) {
    if (!mesh_limits::valid_node(value))
      return;
    this->allowed_nodes_ |= uint16_t(1U << (value - 1));
  }
  void add_peer(uint8_t node_id, const std::array<uint8_t, 6> &mac, const std::array<uint8_t, 16> &lmk) {
#ifndef USE_MESH_AUTO
    if (mesh_limits::valid_node(node_id))
      this->manual_bindings_[node_id - 1].mac = mac;
#endif
    this->transport_.add_peer(node_id, mac, lmk);
  }

  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }
  void on_safe_shutdown() override;
  void on_shutdown() override;
  bool teardown() override;

  bool send_probe(uint8_t destination);
  bool start_probe_benchmark(uint8_t destination, uint16_t count = 100, uint32_t interval_ms = 1000);
  void stop_probe_benchmark();
  bool benchmark_active() const;
  bool send_wifi_fault(uint8_t destination, uint32_t duration_ms);
  bool send_wifi_recover(uint8_t destination);
  void start_wifi_fault(uint32_t duration_ms);
  void clear_wifi_fault();

  uint8_t root_id() const;
  uint8_t parent_id() const;
  uint8_t rank() const;
  bool mesh_connected() const;
  bool mesh_connection_active() const;
  bool wifi_fault_active() const;
  uint32_t received_count() const;
  uint32_t forwarded_count() const;
  uint32_t rx_drop_count() const;
  uint32_t tx_drop_count() const;
  uint32_t probe_reply_count() const;

 protected:
  static MeshComponent *instance_;
  static bool accept_frame_(void *context, const ::mesh_transport::ReceiveMetadata &metadata,
                            const ::mesh_core::Frame &frame);
  static void received_frame_(void *context, uint32_t now);
  static void core_deliver_(void *context, const ::mesh_core::Frame &frame);
  static void core_route_changed_(void *context, const ::mesh_core::RouteSnapshot &route);
  static void transport_task_(void *context);
  static void wake_transport_(void *context);
  void transport_tick_();
  void shutdown_tick_(uint32_t now);
  bool initialize_runtime_(bool preserve_ip_replay = false);
  uint64_t identity_session_(uint8_t node) const;
#ifndef USE_MESH_AUTO
  static uint64_t manual_session_(void *context, ::mesh_core::NodeId node);
  void manual_session_receive_(const ::mesh_core::Frame &frame);
  void manual_session_tick_(uint32_t now);
#endif
#ifdef USE_MESH_AUTO
  static uint64_t auto_session_(void *context, ::mesh_core::NodeId node);
  bool auto_setup_();
  void auto_tick_(uint32_t now, bool direct);
  void auto_loop_();
  bool auto_identity_allowed_(uint8_t node, const std::array<uint8_t, 6> &mac) const;
  bool auto_neighbor_allowed_(const std::array<uint8_t, 6> &mac) const;
  static bool auto_auth_send_(void *, const ::mesh_auto::Mac &, const uint8_t *, size_t);
  static void auto_authenticated_(void *, const ::mesh_auto::PeerIdentity &);
  static void auto_revoked_(void *, const ::mesh_auto::Mac &);
  static bool auto_membership_send_(void *, const uint8_t *, size_t);
  static uint64_t auto_challenge_(void *);
  static void auto_slot_changed_(void *, const ::mesh_membership::SlotChange &);
  static void auto_local_changed_(void *, uint8_t, uint8_t, ::mesh_membership::LocalChange);
  std::unique_ptr<AutomaticMeshState> auto_;
#endif
  void ip_tick_(uint32_t now, bool associated);
#ifdef MESH_IPV6
  bool ipv6_control_(const ::mesh_core::Frame &frame);
  void ipv6_tick_(uint32_t now, bool direct);
  uint32_t last_ipv6_status_{0};
#ifdef USE_MESH_DISCOVERY
  uint32_t ipv6_discovery_generation_{0}, last_ipv6_discovery_{0};
  size_t ipv6_discovery_offset_{0};
#endif
#endif
  void select_ip_gateway_(uint32_t now);
  void drop_obsolete_ip_tx_();
  bool ip_status_deliver_(const ::mesh_core::Frame &frame);
  bool ip_quiet_ack_deliver_(const ::mesh_core::Frame &frame);
  void ip_quiet_ack_tick_(uint32_t now);
  bool endpoint_deliver_(const ::mesh_core::Frame &frame);
  void endpoint_tick_(uint32_t now, bool direct);
  bool gateway_service_() const {
    return this->ip_gateways_ != 0 ? this->gateway_candidate_(this->node_id_)
                                   : (this->ip_gateway_ != 0 && this->node_id_ == this->ip_gateway_);
  }
  bool gateway_candidate_(uint8_t node) const {
    if (node < 1 || node > mesh_limits::MAX_NODES || !(this->ip_gateways_ & (1U << (node - 1))))
      return false;
#ifdef USE_MESH_AUTO
    if (this->auto_) {
      if (this->auto_->quarantined)
        return false;
      if (node == this->node_id_)
        return this->auto_->gateway;
      const auto *member = this->auto_->members ? this->auto_->members->find(node) : nullptr;
      return member != nullptr && (member->flags & ::mesh_membership::kGatewayCapable) &&
             (this->auto_->ready_mask & (1U << (node - 1)));
    }
#endif
    return true;
  }
  uint16_t known_gateway_mask_() const;
#ifdef USE_MESH_DISCOVERY
  void discovery_loop_();
  void discovery_tick_(uint32_t now, bool associated);
#endif
  void ip_deliver_(const ::mesh_core::Frame &frame);
  bool ip_accept_(uint8_t source, const uint8_t *packet, size_t length);
  static bool ip_send_fragment_(void *context, uint8_t destination, const uint8_t *packet, size_t length);
  static bool ip_send_ack_(void *context, uint8_t destination, const uint8_t *packet, size_t length);
  static bool ip_accept_packet_(void *context, uint8_t source, const uint8_t *packet, size_t length);
  void begin_ip_handover_();
  uint32_t mesh_ownership_address_(uint32_t now) const;
  void finish_wifi_recover_();
  void cancel_native_recovery_();
  void enter_mesh_radio_();
  void maybe_probe_wifi_();
  void maybe_search_channel_();
  void dhcp_tick_(uint32_t now, bool direct);
  void begin_dhcp_probe_(uint32_t now);
  void accept_mesh_lease_();
  static void set_mesh_dns_(void *context);

  void deliver_(const ::mesh_core::Frame &frame);
  bool allowed_(uint8_t node_id) const;
  bool send_control_(uint8_t destination, uint8_t command, uint32_t duration_ms);
  bool start_unassociated_radio_();
  ::mesh_radio::RadioTxState capture_radio_state_(bool diagnostic) const;
  void update_radio_lifecycle_(const ::mesh_radio::RadioTxState &state);
  void update_roaming_suppression_(bool needed);
  bool radio_tx_allowed_(const ::mesh_radio::RadioTxState &state) const;
  uint8_t refresh_radio_channel_(bool direct, bool roaming, bool sample);
  bool transport_has_room_(size_t reserve = 8) const;
  size_t transport_payload_mtu_() const;
  bool send_probe_(uint8_t destination, uint32_t run);
  void benchmark_tick_(uint32_t now);
  struct PendingProbe {
    bool used{false};
    uint8_t peer{0};
    uint16_t sequence{0};
    uint32_t sent_ms{0};
    uint32_t sent_us{0};
    uint32_t run{0};
  };
  static constexpr uint32_t PROBE_TIMEOUT_MS = 2000;
  static constexpr size_t BENCHMARK_PAYLOAD_SIZE = 32;
  PendingProbe pending_probes_[32]{};
  bool benchmark_active_{false};
  uint32_t benchmark_boot_{0};
  uint32_t benchmark_run_{0};
  uint8_t benchmark_peer_{0};
  uint16_t benchmark_count_{0};
  uint16_t benchmark_sent_{0};
  uint32_t benchmark_interval_{1000};
  uint32_t benchmark_last_send_{0};

  uint8_t node_id_{1};
  uint8_t channel_{1};
  uint8_t cached_channel_{1};
  uint16_t allowed_nodes_{0};
  EspNowTransport transport_;
  ::mesh_transport::ManagementChannel management_;
  std::unique_ptr<::mesh_core::MeshRuntime> runtime_;
  ::mesh_core::MeshCore *core_{nullptr};  // Owned by runtime_.
  std::array<uint8_t, 6> own_mac_{};      // LAN endpoint identity, independent of backend.
#ifdef USE_MESH_IP
  MeshNetworkProvider network_provider_;
#endif
  std::atomic<uint32_t> rx_drops_{0};
  uint32_t tx_drops_{0};
  uint32_t probe_replies_{0};
  uint32_t last_status_{0};
  uint8_t diagnostic_phase_{0};
  uint8_t radio_rate_diagnostic_node_{1};
  uint16_t sequence_{0};
  bool last_direct_uplink_{false};
  bool roaming_suppression_held_{false};  // Worker-owned, one stock Wi-Fi request.
  bool wifi_fault_active_{false};
  uint32_t wifi_fault_started_{0};
  uint32_t wifi_fault_duration_{0};
  // A received command is applied after MeshCore::receive returns (no reentry).
  uint8_t pending_command_{0};
  uint32_t pending_duration_{0};
  uint8_t ip_gateway_{0};
  uint16_t ip_gateways_{0};
  bool gateway_revalidate_{false};
  uint64_t endpoint_session_{0};
#ifndef USE_MESH_AUTO
  ::mesh_session::ManualBootSessionRegistry manual_sessions_;
  struct ManualBinding {
    std::array<uint8_t, 6> mac{};
    uint64_t boot{0};
    uint32_t epoch{0};
    bool netif_done{false}, mdns_done{false};
  };
  ManualBinding manual_bindings_[mesh_limits::MAX_NODES]{};
  uint32_t manual_epoch_{0};
#endif
  uint64_t endpoint_replies_[mesh_limits::MAX_NODES]{};
  ::mesh_ip::ChallengeRegistry endpoint_challenges_;
  uint32_t last_endpoint_challenge_{0}, last_endpoint_witness_{0}, last_witness_refresh_{0};
#ifndef MESH_IP_CLIENT_ONLY
  struct PendingEndpointWitness {
    bool used{false};
    uint32_t started{0};
    uint32_t address{0}, lease_id{0};
  };
  PendingEndpointWitness pending_endpoint_witness_[mesh_limits::MAX_NODES]{};
#endif
  bool mesh_radio_active_{false}, native_recover_pending_{false};
  bool radio_start_pending_{false}, native_handover_attempt_{false}, last_native_requested_{false};
  uint32_t last_radio_start_{0};
  bool route_stability_{false};
  ::mesh_radio::ChannelSearch channel_search_;
  ::mesh_radio::RadioOwnership radio_ownership_;
  uint8_t received_ad_sender_{0}, received_ad_channel_{0};
  bool channel_hop_pending_{false}, channel_switch_active_{false}, wifi_scan_active_{false};
  uint32_t last_wifi_probe_{0};
  ::mesh_radio::NativeRecovery native_recovery_;
  std::array<::mesh_radio::NativeWifiNetwork, MESH_NATIVE_WIFI_NETWORK_COUNT> native_wifi_networks_{};
  ::mesh_radio::NativeWifiCandidate native_wifi_candidate_{};
  uint32_t last_wifi_restore_{0};
  uint8_t wifi_scan_home_{0};
  bool wifi_restore_pending_{false}, wifi_probe_found_{false};
  ::mesh_ip::DhcpClient dhcp_client_;
  bool dhcp_lease_installed_{false}, dhcp_probe_pending_{false};
  uint32_t last_dhcp_probe_{0};
  std::atomic<uint32_t> mesh_dns_{0};
  struct PendingLeaseResult {
    bool used{false};
    uint8_t payload[11]{};
  };
#ifndef MESH_IP_CLIENT_ONLY
  PendingLeaseResult pending_lease_results_[mesh_limits::MAX_NODES]{};
#endif
  ::mesh_ip::PacketDelivery ip_delivery_;
  // The worker owns reliable delivery; the IP adapter crosses into lwIP by queues.
  ::mesh_ip::MeshIpNetif ip_netif_;
#ifdef USE_MESH_DISCOVERY
  MeshIpMdns ip_mdns_;
#ifndef MESH_IP_GATEWAY_ONLY
  uint8_t discovery_descriptor_[::mesh_ip::DISCOVERY_DESCRIPTOR_MAX]{};
  size_t discovery_length_{0}, discovery_offset_{0};
  uint32_t last_discovery_{0};
  bool discovery_was_active_{false};
  // Each LAN edge completes independently; an absent edge cannot force
  // successful chunks to be queued repeatedly to every surviving edge.
  uint16_t discovery_gateway_offsets_[mesh_limits::MAX_NODES]{};
  uint32_t discovery_gateway_attempts_[mesh_limits::MAX_NODES]{};
  uint32_t discovery_metadata_digest_{0}, discovery_metadata_address_{0};
  uint32_t last_discovery_metadata_check_{0};
  uint16_t discovery_metadata_length_{0};
#endif
#endif
  ::mesh_ip::OwnershipHandover ip_handover_;
  ::mesh_ip::OwnershipHandover dhcp_quiet_;
  uint32_t ip_handover_address_{0};
  struct PendingIpAck {
    bool used{false};
    uint8_t payload[11]{};
  };
#ifndef MESH_IP_CLIENT_ONLY
  PendingIpAck pending_ip_acks_[mesh_limits::MAX_NODES]{};
#endif
  bool ip_tx_active_{false};
  uint32_t ip_packet_sequence_{0};
  uint32_t last_ip_update_{0};
  uint32_t last_ip_status_{0};
  uint32_t ip_received_{0};
  uint32_t ip_sent_{0};
  uint32_t ip_reassembly_drops_{0};
  mutable StaticSemaphore_t mutex_storage_{};
  mutable SemaphoreHandle_t mutex_{nullptr};
  TaskHandle_t transport_task_handle_{nullptr};
  std::atomic<TaskHandle_t> transport_wake_handle_{nullptr};
  std::atomic<uint32_t> transport_wake_users_{0};
  std::atomic<bool> transport_stop_{false};
  std::atomic<bool> transport_exited_{true};
  std::atomic<bool> shutdown_requested_{false};
  std::atomic<bool> shutdown_handover_done_{false};
  bool shutdown_hook_seen_{false};          // Application-owned.
  bool shutdown_handover_started_{false};   // Worker-owned.
  bool shutdown_handover_required_{false};  // Worker-owned.
};

}  // namespace esphome::mesh
