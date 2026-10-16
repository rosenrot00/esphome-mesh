#pragma once

#include "mesh_limits.h"
#include "esphome/components/espnow_driver/espnow_driver.h"

#include "mesh_core.h"
#include "mesh_transport.h"
#include "mesh_management.h"
#include "mesh_radio_rate.h"
#include <array>
#include <atomic>
#include <esp_idf_version.h>
#include <esp_now.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

namespace esphome::mesh {

// Concrete ESP-NOW backend. The common SDK owner grants this adapter an exclusive lease.
// Provision before start(); worker methods have one owner. Only SDK callbacks
// cross tasks, through the bounded RX queue and atomic TX result mailbox.
// No ESPHome Component, Wi-Fi policy, IP, DHCP or discovery dependency.
class EspNowTransport {
 public:
  EspNowTransport();
  static constexpr size_t RX_CAPACITY = mesh_limits::RADIO_RX_CAPACITY;
  static constexpr size_t TX_CAPACITY = mesh_limits::RADIO_TX_CAPACITY;
  static constexpr size_t NATIVE_FRAME_BUDGET = mesh_limits::NATIVE_FRAME_BUDGET;
#ifndef ESP_NOW_MAX_DATA_LEN_V2
#error "ESP-NOW v2 transport requires an SDK with ESP_NOW_MAX_DATA_LEN_V2"
#else
  static_assert(NATIVE_FRAME_BUDGET <= ESP_NOW_MAX_DATA_LEN_V2, "Native frame exceeds the SDK v2 limit");
#endif
  static constexpr size_t MAX_PEERS = mesh_limits::MAX_PEERS;
  static constexpr size_t MANAGEMENT_CAPACITY = 8;
  static constexpr size_t MANAGEMENT_WIRE_SIZE = 128;
  // Continuous relay reception, independent of the station modem-sleep mode.
  // These describe the configured SDK contract, not measured RF availability.
  static constexpr uint16_t RECEIVE_WINDOW_MS = 65535;
  static constexpr uint16_t RECEIVE_INTERVAL_MS = 0;
  static constexpr uint16_t SEND_CALLBACK_TIMEOUT_MS = 2000;
  static constexpr uint16_t RECOVERY_MIN_MS = 500;
  static constexpr uint16_t RECOVERY_MAX_MS = 5000;
  static constexpr uint16_t SDK_NO_MEM_COOLDOWN_MS = 250;
  static constexpr size_t CLASS_CAPACITY_PER_PEER = 4;
  static constexpr uint8_t DATA_BURST_LIMIT = 3;
  static constexpr uint16_t LINK_RETRY_MIN_MS = 15;
  static constexpr uint16_t LINK_RETRY_MAX_MS = 60;
  using MacAddress = std::array<uint8_t, 6>;
  struct ManagementPacket {
    MacAddress source{};
    uint8_t channel{0};
    uint16_t length{0};
    uint8_t data[MANAGEMENT_WIRE_SIZE]{};
  };
  ::mesh_transport::ManagementTransport management_backend();
  void set_node_id(uint8_t value) { node_id_ = value; }
  void set_pmk(const std::array<uint8_t, 16> &value) { pmk_ = value; }
  bool add_peer(uint8_t node, const std::array<uint8_t, 6> &mac, const std::array<uint8_t, 16> &lmk);
  // Register before SDK startup; replacing the context requires SDK quiescence.
  // Clearing is nonblocking: a previously captured callback may still finish.
  // The callback/context must therefore remain valid until callbacks quiesce.
  void set_wake_callback(void *context, ::mesh_transport::WakeCallback callback);
  // Discovery is a separate, bounded plaintext carrier for authenticated
  // management messages. No management packet is returned to MeshCore.
  // Configure before start(). Recipient binding and authentication belong to
  // the security engine; all carrier sends use the ESP-NOW broadcast peer.
  bool set_management_enabled(bool enabled);
  bool enqueue_management(const MacAddress &destination, const uint8_t *data, size_t length, uint32_t now);
  bool poll_management(ManagementPacket &packet);
  // The serial worker calls these only after admission by the identity registry.
  // Refuse mutation while a send awaits its SDK callback. Retrying is safe.
  // Existing MACs can be rebound/rekeyed; conflicting identities are rejected.
  bool install_authenticated_peer(uint8_t node, const MacAddress &mac, const std::array<uint8_t, 16> &lmk);
  bool remove_authenticated_peer(uint8_t node);
  bool peer_address(uint8_t node, MacAddress &mac) const;
  bool start();
  void stop();
  // Integration-owned lifecycle permission, independent of TX admission.
  // Enabling only grants permission; ready() confirms successful startup.
  // Disabling is nonblocking on failure and returns true only after actual
  // SDK quiescence. Failed teardown keeps callback/queue ownership fenced.
  bool set_sdk_enabled(bool enabled);
  bool sdk_enabled() const { return sdk_enabled_; }
  bool sdk_quiescent() const { return !sdk_initialized_ && !tx_inflight_; }
  bool ensure_started(uint32_t now);
  bool ready() const { return espnow_ready_; }
  bool continuous_receive_ready() const { return espnow_ready_; }
  bool busy() const { return tx_inflight_; }
  bool enqueue(uint8_t next_hop, const ::mesh_core::Frame &frame, uint32_t now);
  bool poll_receive(::mesh_transport::ReceiveMetadata &metadata, ::mesh_core::Frame &frame);
  void process(uint32_t now, bool allow_start = true);
  // Retain the outstanding queue entry until callback or successful teardown,
  // but disable retry. This preserves send/result association conservatively;
  // the SDK itself copies data before esp_now_send returns. Even
  // keep_inflight=false retains that entry while clearing pending entries.
  void cancel_pending(bool keep_inflight = true);
  void discard_receive();
  size_t pending_count() const { return tx_count_; }
  constexpr size_t capacity() const { return TX_CAPACITY; }
  size_t peer_count() const { return peer_count_; }
  uint32_t rx_drop_count() const { return rx_drops_.load(); }
  uint32_t tx_drop_count() const { return tx_drops_; }
  uint32_t failure_count() const { return tx_failures_; }
  uint32_t sdk_no_mem_count() const { return sdk_no_mem_count_; }
  // Actual accepted entries discarded, distinct from rejected admissions that
  // an upper layer can retry without losing its datagram.
  uint32_t queue_expiry_count() const { return queue_expiries_; }
  uint32_t retry_exhausted_count() const { return retry_exhausted_; }
  using PeerRate = ::mesh_radio::LinkRate;
  struct PeerRateStats {
    PeerRate configured{PeerRate::UNKNOWN};
    uint32_t observed_base_success{0}, observed_fast_success{0};
  };
  bool peer_rate(uint8_t node, PeerRateStats &stats) const;
  uint16_t configured_fast_mask() const;
  uint32_t rate_probe_count() const { return rate_probes_; }
  uint32_t rate_fallback_count() const { return rate_fallbacks_; }
  uint32_t rate_error_count() const { return rate_errors_; }
  static constexpr bool rate_observation_supported() { return ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0); }
  const std::array<uint8_t, 6> &local_address() const { return own_mac_; }
  ::mesh_transport::Transport transport(::mesh_transport::InterfaceId id = ::mesh_transport::kDefaultInterface);

 protected:
  struct Peer {
    uint8_t node_id;
    std::array<uint8_t, 6> mac;
    std::array<uint8_t, 16> lmk;
  };
  struct RxPacket {
    MacAddress source;
    uint32_t binding_generation;
    uint8_t binding_slot;
    uint8_t sender;
    uint8_t channel;
    uint16_t length;
    uint8_t data[::mesh_core::kMaxWireSize];
  };
  struct TxPacket {
    uint8_t peer_index;
    uint8_t attempts;
    uint16_t length;
    uint32_t queued_at;
    uint8_t data[::mesh_core::kMaxWireSize];
  };
  struct ManagementTxPacket {
    uint32_t queued_at;
    uint16_t length;
    uint8_t data[MANAGEMENT_WIRE_SIZE];
  };
  // Callback readers never inspect the mutable peer table. Atomic generations
  // also reject a mixed snapshot while the worker publishes a changed binding.
  struct PeerLookup {
    std::atomic<uint32_t> generation{0}, low{0}, high{0}, node{0};
  };
  static std::atomic<EspNowTransport *> instance_;
  static void receive_callback_(const esp_now_recv_info_t *info, const uint8_t *data, int length);
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 5, 0)
  static void send_callback_(const esp_now_send_info_t *info, esp_now_send_status_t status);
#else
  static void send_callback_(const uint8_t *mac, esp_now_send_status_t status);
#endif
  const espnow_driver::Consumer sdk_consumer_{receive_callback_, send_callback_};
  int peer_index_(const uint8_t *mac) const;
  uint8_t callback_node_(const uint8_t *mac, uint8_t *slot = nullptr, uint32_t *generation = nullptr) const;
  void publish_peer_(size_t index);
  void discard_peer_tx_(size_t index, bool compact);
  void set_send_destination_(const uint8_t *mac);
  bool start_at_(uint32_t now);
  bool teardown_sdk_();
  bool service_disabled_(uint32_t now);
  void clear_pending_();
  void finish_teardown_();
  void schedule_recovery_();
  void sdk_no_mem_(const char *origin, uint8_t peer = 0);
  bool peer_failed_(size_t peer, uint8_t attempts, uint32_t now);
  bool prepare_peer_rate_(size_t peer, uint32_t now);
  bool apply_peer_rate_(size_t peer, PeerRate rate);
  void reset_peer_rate_(size_t peer, bool clear_observed);
  bool send_management_(uint32_t now);
  void prune_tx_(uint32_t now);
  TxPacket &tx_packet_(size_t offset = 0) { return tx_queue_[tx_order_[(tx_head_ + offset) % TX_CAPACITY]]; }
  const TxPacket &tx_packet_(size_t offset = 0) const {
    return tx_queue_[tx_order_[(tx_head_ + offset) % TX_CAPACITY]];
  }
  void remove_tx_(size_t offset);
  void notify_worker_() const;
  uint8_t node_id_{1};
  ::mesh_transport::InterfaceId interface_id_{::mesh_transport::kDefaultInterface};
  std::array<uint8_t, 16> pmk_{};
  std::array<uint8_t, 6> own_mac_{};
  Peer peers_[MAX_PEERS]{};
  PeerLookup peer_lookup_[MAX_PEERS]{};
  size_t peer_count_{0};
  StaticQueue_t rx_queue_storage_{};
  uint8_t rx_queue_buffer_[RX_CAPACITY * sizeof(RxPacket)]{};
  // The SDK Wi-Fi task's stack is outside our control. A native v2 callback
  // must not add a 1.5KB automatic object to it. The sole nonblocking callback
  // writer owns this scratch until the static RX queue has taken its copy.
  RxPacket rx_callback_packet_{};
  std::atomic<bool> rx_callback_busy_{false};
  QueueHandle_t rx_queue_{nullptr};
  std::atomic<uint32_t> rx_drops_{0};
  StaticQueue_t management_rx_storage_{};
  uint8_t management_rx_buffer_[MANAGEMENT_CAPACITY * sizeof(ManagementPacket)]{};
  QueueHandle_t management_rx_queue_{nullptr};
  ManagementTxPacket management_tx_[MANAGEMENT_CAPACITY]{};
  size_t management_tx_head_{0}, management_tx_tail_{0}, management_tx_count_{0};
  TxPacket tx_queue_[TX_CAPACITY]{};
  // A permutation of all fixed payload slots. The active logical ring owns
  // its first tx_count_ entries; the rest are free. Scheduling moves only IDs.
  uint8_t tx_order_[TX_CAPACITY]{};
  size_t tx_head_{0}, tx_tail_{0}, tx_count_{0}, tx_next_peer_{0};
  uint32_t tx_peer_failed_at_[MAX_PEERS]{};
  uint16_t tx_peer_backoff_[MAX_PEERS]{};
  uint8_t tx_peer_data_burst_[MAX_PEERS]{};
  uint8_t tx_peer_failure_streak_[MAX_PEERS]{};
  ::mesh_radio::LinkProbe tx_peer_rate_[MAX_PEERS]{};
  uint32_t observed_base_success_[MAX_PEERS]{}, observed_fast_success_[MAX_PEERS]{};
  // -1 idle, -2-peer_index awaiting that peer. A nonnegative result packs
  // success in bit 0 and the callback's rate class in bits 1..2 (0 unknown,
  // 1 base, 2 fast, 3 other). Result and rate publish in one atomic operation.
  std::atomic<int> send_result_{-1};
  std::atomic<bool> callbacks_enabled_{false};
  // The RISC-V targets do not all provide lock-free pointer atomics. A short
  // SDK-task-safe critical section snapshots just this pair, never the hook.
  mutable portMUX_TYPE wake_lock_ = portMUX_INITIALIZER_UNLOCKED;
  ::mesh_transport::WakeCallback wake_callback_{nullptr};
  void *wake_context_{nullptr};
  std::atomic<uint32_t> send_destination_low_{0}, send_destination_high_{0};
  bool tx_inflight_{false}, espnow_ready_{false}, descriptor_exported_{false};
  bool management_enabled_{false}, management_inflight_{false}, last_send_management_{false};
  bool sdk_enabled_{true}, sdk_initialized_{false}, stop_requested_{false}, recovery_packet_pending_{false};
  bool recovery_waiting_{false}, tx_cooldown_active_{false};
  uint16_t recovery_backoff_{0};
  uint32_t recovery_at_{0}, tx_cooldown_at_{0}, sdk_no_mem_count_{0}, last_no_mem_log_{0};
  uint32_t tx_started_{0}, tx_drops_{0}, tx_failures_{0}, last_init_attempt_{0};
  uint32_t accepted_{0}, rejected_{0}, sent_{0}, received_{0};
  uint32_t queue_expiries_{0}, retry_exhausted_{0};
  uint32_t rate_probes_{0}, rate_fallbacks_{0}, rate_errors_{0};
};

}  // namespace esphome::mesh
