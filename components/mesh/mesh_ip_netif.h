#pragma once
#include "mesh_native_uplink.h"

#include "mesh_limits.h"

#include "mesh_ip_role.h"
#include "mesh_ip_queue.h"
#ifdef MESH_IPV6
#include "mesh_ip_ipv6.h"
#endif

#include <atomic>
#include <cstddef>
#include <cstdint>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <lwip/netif.h>

namespace mesh_ip {

struct DhcpMessage;

// Raw IPv4 adapter for the mesh lab. Addresses use lwIP/network byte
// order. The portable DHCP client owns lease lifetime; this adapter carries its
// tightly scoped bootstrap packets and installs/withdraws a validated lease.
class MeshIpNetif {
 public:
  static constexpr size_t MAX_PACKET_SIZE = 1500;
  static constexpr size_t receive_capacity() { return RX_CAPACITY; }
  using IpPacket = QueuedIpPacket;
  struct Counters {
    uint32_t mesh_tx, mesh_rx, queue_drops, invalid_packets, proxy_arp, lan_tx, flow_backpressure, rx_retries;
  };
  struct LeaseProbeResult {
    uint8_t node_id{0};
    uint32_t address{0}, nonce{0};
    bool conflict{false};
    uint32_t generation{0}, peer_epoch{0};
  };

  bool configure(uint8_t node_id, uint8_t gateway_id, bool require_dhcp = false, uint16_t gateway_candidates = 0);
  // Call from the mesh worker when its selected root changes. Zero withdraws
  // the route. In candidate mode this changes only client egress: the validated
  // lease and independently active LAN gateway service remain intact.
  bool select_gateway(uint8_t gateway_id);
  uint8_t selected_gateway() const { return this->gateway_id_.load(); }
  // Cache a nonzero DHCP address while connected. Passing zero on disconnect
  // retains the address for this short, controlled lease-preserving experiment.
  void update(uint32_t ip, uint32_t mask, uint32_t gateway, bool station_connected, bool mesh_reachable,
              NativeUplink uplink = NativeUplink::NATIVE_UPLINK_WIFI);
  // Configure before receiving mesh traffic, including nodes beyond one hop.
  // A gateway never forwards DHCP using a client MAC supplied only on the wire.
  bool set_dhcp_peer_mac(uint8_t node_id, const uint8_t *mac);
  // Worker-owned request, TCP/IP-owned reset/publication. Retrying the same
  // nonzero identity epoch is idempotent. A new epoch resets even the same MAC
  // (e.g. a new boot session); null revokes the slot. False means retry until
  // old DHCP/witness/proxy/queued state is gone. Keep mesh admission closed.
  bool update_peer_identity(uint8_t node_id, const uint8_t *mac, uint32_t identity_epoch);
  void set_gateway_enabled(bool enabled) {
    this->gateway_enabled_.store(enabled);
    this->schedule_();
  }
  bool submit_dhcp_request(const uint8_t *packet, size_t length);
  bool install_valid_lease(uint32_t ip, uint32_t mask, uint32_t gateway);
  void clear_mesh_lease();
  bool begin_lease_probe(uint8_t node_id, uint32_t address, uint32_t nonce);
  bool pop_probe_result(LeaseProbeResult &result);
  bool set_peer(uint8_t node_id, uint32_t ip, bool fallback_active);
  // Witness export is restricted to an ACK actually observed on this node's
  // LAN; imported witnesses are never re-exported as local server evidence.
  bool local_lease_witness(uint8_t node_id, uint32_t &address, uint32_t &xid, uint32_t &remaining_seconds) const;
  // The caller authenticates the configured witness-source candidate. Remote
  // evidence never replaces a local ACK; after the first client challenge it
  // must match that client's freshly proved identity. Repeats cannot extend it.
  bool install_peer_witness(uint8_t node_id, uint32_t address, uint32_t xid, uint32_t remaining_seconds);
  // A nonblocking grant publication can be busy despite a valid witness. This
  // atomic snapshot distinguishes retry/backpressure from missing DHCP proof.
  bool has_lease_witness(uint8_t node_id, uint32_t address, uint32_t xid) const;
  // Called only after endpoint challenge/nonce validation by the component.
  // A missing witness still records the desired identity, allowing its next
  // matching import. Busy calls have no side effects. Same-IP rollover retains
  // an earlier grant until its own original hard deadline/freshness expires.
  bool authorize_endpoint(uint8_t node_id, uint32_t address, uint32_t lease_id, uint32_t remaining_seconds,
                          uint32_t fresh_budget_ms);
  bool withdraw_endpoint(uint8_t node_id);
  // Cooperative handover: withdraw this gateway's cached address ownership
  // before acknowledging release. Also works after demotion. False during an
  // in-flight driver publication means the mesh worker should retry.
  bool revoke_peer(uint8_t node_id, uint32_t address, uint32_t lease_xid);
  // A delegated LAN advertisement is allowed only while this same adapter
  // would forward traffic to that current, lease-valid mesh owner.
  uint32_t peer_mesh_address(uint8_t node_id) const;
  // Fresh validated IPv4 owners or authenticated IPv6 fallback claims,
  // including pending DAD. Safe to sample from the mesh worker.
  bool has_active_mesh_clients() const;
  // Setup/exit may change this optional notification binding. The callback is
  // nonblocking and must not re-enter the adapter or transport. Clearing it
  // prevents new snapshots; a previously captured call may still finish, so
  // context must remain alive and the receiver must invalidate its task handle
  // before deleting the worker. No payload is owned by the callback.
  void set_transport_wake(void *context, void (*wake)(void *));
  // A full-size destination preserves DRR ordering without a second packet
  // scratch. False never transfers a packet to the caller.
  bool consume_outgoing(uint8_t *target, size_t capacity, QueuedIpMetadata &metadata);
  bool pop_outgoing(IpPacket &packet);
  bool deliver_mesh(uint8_t source, const uint8_t *packet, size_t length);
  bool available() const {
#ifdef MESH_IPV6
    return this->ipv4_available() || this->ipv6_available();
#else
    return this->ipv4_available();
#endif
  }
  bool ipv4_available() const {
    return this->available_.load() &&
           (this->station_connected_.load() || (this->role_current_() && this->mesh_path_validated_.load()));
  }
  bool ready() const {
#ifdef MESH_IPV6
    Ipv6AddressSnapshot snapshot;
    if (this->local_ipv6_claim(snapshot) && snapshot.count != 0)
      return true;
#endif
    return this->ready_.load();
  }
  bool fallback_active() const {
#ifdef MESH_IPV6
    if (!this->station_connected_.load() && this->ipv6_available())
      return true;
#endif
    return this->fallback_active_.load() && this->role_current_() && this->mesh_path_validated_.load();
  }
  uint32_t address() const { return this->address_.load(); }
  uint32_t tcpip_stack_min() const {
    const uint32_t value = this->tcpip_stack_min_.load();
    return value == UINT32_MAX ? 0 : value;
  }
  Counters counters() const;
#ifdef MESH_IPV6
  void set_local_mac(const uint8_t mac[6]);
  bool ipv6_available() const;
  bool native_ipv6_ready() const { return this->ipv6_native_ready_.load(); }
  bool local_ipv6_snapshot(Ipv6AddressSnapshot &snapshot) const;
  bool local_ipv6_claim(Ipv6AddressSnapshot &snapshot) const;
  bool peer_ipv6_snapshot(uint8_t node_id, Ipv6AddressSnapshot &snapshot) const;
  bool peer_ipv6_address_valid(uint8_t node_id, const Ipv6Address &address) const;
  bool apply_peer_ipv6_claim(uint8_t node_id, const Ipv6AddressSnapshot &snapshot, bool fallback);
  bool accept_ipv6_grant(uint8_t node_id, const Ipv6AddressSnapshot &snapshot);
#endif

 protected:
  static constexpr size_t TX_CAPACITY = IpFlowQueue::CAPACITY;
  static constexpr size_t RX_CAPACITY = 6;
  static constexpr size_t ARP_CAPACITY = 8;
  static constexpr uint32_t PEER_LEASE_MS = 5000;
  static constexpr uint32_t DHCP_TRANSACTION_MS = 30000;
  static constexpr size_t PROBE_QUEUE_CAPACITY = 8;
  struct Peer {
    std::atomic<uint32_t> generation{0};
    std::atomic<uint32_t> ip{0};
    std::atomic<uint32_t> seen{0};
    std::atomic<bool> fallback{false};
    std::atomic<bool> endpoint{false};
    std::atomic<uint32_t> lease_id{0};
    std::atomic<uint32_t> lease_started{0}, lease_seconds{0};
    // The client, never competing gateway XIDs, chooses the next identity.
    std::atomic<bool> identity_known{false};
    std::atomic<uint32_t> desired_address{0}, desired_xid{0};
    uint32_t last_announcement{0};  // TCP/IP thread only.
    bool announced{false};
  };
  struct ArpRequest {
    uint32_t generation;
    uint32_t peer_epoch;
    uint8_t peer;
    uint32_t claimed_ip;
    uint32_t target_ip;
    uint8_t target_mac[6];
  };
  struct DhcpTransaction {
    // TCP/IP worker is the sole writer. The Wi-Fi driver reads an atomic
    // snapshot without taking a lock or blocking the radio task.
    std::atomic<uint32_t> generation{0}, xid{0}, seen{0};
    std::atomic<uint8_t> request_type{0};
    std::atomic<uint32_t> mac_low{0}, mac_high{0};
    std::atomic<uint32_t> candidate_xid{0}, candidate_address{0};
  };
  struct LeaseProbe {
    std::atomic<uint32_t> address{0};
    std::atomic<uint8_t> phase{0};  // 0 idle, 1 probing, 2 cached result.
    std::atomic<bool> conflict{false};
    uint32_t nonce{0}, last_probe{0}, completed{0}, generation{0}, peer_epoch{0};  // TCP/IP thread only.
    uint8_t attempts{0};
  };
  struct DhcpOwnership {
    std::atomic<bool> managed{false}, active{false}, revoked{false};
    std::atomic<bool> local{false};
    // Only the driver marks ACKs local. Witness imports and request/revocation
    // updates share the same nonblocking publication guard with that driver.
    std::atomic<uint32_t> generation{0}, address{0}, xid{0}, seconds{0}, started{0}, revoked_xid{0},
        revoked_lease_xid{0};
  };
  struct RemoteWitness {
    std::atomic<bool> active{false};
    std::atomic<uint32_t> generation{0}, address{0}, xid{0}, seconds{0}, started{0};
  };
  static MeshIpNetif *instance_;
  static err_t netif_init_(struct netif *netif);
  static err_t netif_output_(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination);
  static err_t station_input_(struct pbuf *packet, struct netif *netif);
#ifdef MESH_HAS_ETHERNET
  static err_t lan_input_(struct pbuf *packet, struct netif *netif);
#endif
  static err_t station_output_(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination);
  static void work_callback_(void *context);
  void schedule_();
  void work_();
  void announce_(uint32_t address);
  void arp_reply_(const ArpRequest &request);
  bool arp_probe_(uint32_t address);
  void observe_probe_arp_(const uint8_t *header);
  void work_probes_(bool connected);
  uint8_t peer_for_ip_(uint32_t ip, bool require_fallback) const;
  IpPacket *reserve_outgoing_(const IpFlowQueue::Key &key, IpFlowQueue::Reservation &reservation);
  bool commit_outgoing_(const IpFlowQueue::Reservation &reservation, bool publish = true);
  bool enqueue_(uint8_t destination, const uint8_t *packet, size_t length, bool count_rejection = true,
                uint8_t ingress_source = 0, uint32_t ingress_epoch = 0);
  bool enqueue_(uint8_t destination, struct pbuf *packet, uint16_t offset, uint16_t length, bool from_driver = false);
  static bool valid_ipv4_(const uint8_t *packet, size_t length);
  bool deliver_ipv4_(uint8_t source, const uint8_t *packet, size_t length);
  static bool unicast_address_(uint32_t address);
  bool valid_peer_address_(uint8_t node_id, uint32_t address) const;
  bool valid_dhcp_request_(uint8_t source, const uint8_t *packet, size_t length) const;
  bool track_dhcp_request_(uint8_t source, const uint8_t *packet, size_t length);
  uint8_t dhcp_destination_(const DhcpMessage &message, uint32_t *peer_epoch = nullptr);
  bool capture_dhcp_reply_(struct pbuf *packet, uint16_t length);
  bool gateway_lease_valid_(uint8_t node_id, uint32_t address) const;
  bool witness_remaining_(uint8_t node_id, uint32_t address, uint32_t xid, uint32_t &remaining) const;
  bool endpoint_lease_valid_(uint8_t node_id, uint32_t address) const;
  bool gateway_source_valid_(uint8_t node_id, uint32_t address) const;
  bool candidate_(uint8_t node_id) const;
  bool transport_current_() const;
  bool peer_current_(uint8_t node_id) const;
  bool peer_epoch_current_(uint8_t node_id, uint32_t epoch) const;
  bool role_current_() const;
  bool gateway_active_() const;
  bool apply_gateway_change_(uint32_t generation);
  bool apply_pending_identities_();
#ifdef MESH_HAS_ETHERNET
  bool apply_native_uplink_();
  std::atomic<NativeUplink> native_uplink_{NativeUplink::NATIVE_UPLINK_WIFI};
  std::atomic<NativeUplink> applied_native_uplink_{NativeUplink::NATIVE_UPLINK_WIFI};
  std::atomic<uint32_t> native_uplink_revision_{0}, applied_native_uplink_revision_{0};
#endif
#ifndef MESH_IP_CLIENT_ONLY
  void reset_peer_identity_state_(size_t index);
  bool dhcp_peer_mac_(uint8_t node_id, uint8_t output[6]) const;
#endif

#ifdef MESH_IPV6
  // Every field participating in a cross-task snapshot is atomic; the revision
  // additionally prevents mixing an address with another publication's epoch.
  struct Ipv6Publication {
    std::atomic<uint32_t> revision{0}, generation{0}, peer_epoch{0};
    std::atomic<uint32_t> words[Ipv6AddressSnapshot::CAPACITY][4]{};
    std::atomic<uint8_t> count{0}, preferred_mask{0};
    std::atomic<bool> ready{false};
  };
  struct Ipv6Peer {
    Ipv6Publication requested{}, granted{};
    std::atomic<uint32_t> refreshed{0};
    std::atomic<bool> fallback{false};
    std::atomic<bool> requalify{false};
    std::atomic<uint8_t> conflicts{0};
    Ipv6AddressSnapshot active{};  // TCP/IP owner only.
    uint32_t probe_started[Ipv6AddressSnapshot::CAPACITY]{};
    uint8_t probes[Ipv6AddressSnapshot::CAPACITY]{};
    bool joined[Ipv6AddressSnapshot::CAPACITY]{};
    uint32_t last_announcement{0};
    uint32_t qualification_generation{0};
    uint8_t announcements{0};
  };
  struct Ipv6Prefix {
    std::atomic<uint32_t> revision{0}, words[2]{}, started{0}, lifetime{0};
  };
  static bool read_ipv6_publication_(const Ipv6Publication &, Ipv6AddressSnapshot &);
  static void publish_ipv6_(Ipv6Publication &, const Ipv6AddressSnapshot &);
  static err_t netif_output_ipv6_(struct netif *, struct pbuf *, const ip6_addr_t *);
#ifndef MESH_IP_CLIENT_ONLY
  static err_t station_output_ipv6_(struct netif *, struct pbuf *, const ip6_addr_t *);
  bool station_input_ipv6_(struct pbuf *, bool &consume);
#endif
  bool enqueue_ipv6_(uint8_t destination, struct pbuf *, uint16_t offset, uint16_t length, bool from_driver = false);
  bool deliver_ipv6_(uint8_t source, const uint8_t *, size_t);
  bool process_ipv6_(IpPacket &incoming, bool &flow_blocked);  // false retains or rotates RX for retry.
  void work_ipv6_();
  void reset_ipv6_peer_(size_t index);
  bool ipv6_prefix_valid_(const Ipv6Address &) const;
  bool ipv6_identity_valid_(uint8_t node_id, const Ipv6Address &) const;
  bool ipv6_iid_valid_(uint8_t node_id, const Ipv6Address &) const;
  bool ipv6_peer_active_(uint8_t node_id) const;
  bool ipv6_source_allowed_(uint8_t node_id, const Ipv6PacketInfo &) const;
  bool ipv6_local_address_(const Ipv6Address &, bool tentative = false) const;
  uint8_t peer_for_ipv6_(const Ipv6Address &) const;
  void observe_ipv6_ra_(const Ipv6PacketReader &, const Ipv6PacketInfo &);
  void observe_ipv6_conflict_(const Ipv6PacketInfo &, const uint8_t source_mac[6]);
  bool send_ipv6_dad_(const Ipv6Address &);
  bool send_ipv6_rs_();
  bool send_ipv6_na_(const Ipv6Address &);
  bool ipv6_station_link_() const;
  bool ipv6_forwarding_available_() const;
  Ipv6Publication ipv6_local_{}, ipv6_grant_request_{};
  Ipv6Peer ipv6_peers_[mesh_limits::MAX_NODES]{};
  Ipv6Prefix ipv6_prefixes_[2]{};
  std::atomic<uint32_t> ipv6_mac_low_{0}, ipv6_mac_high_{0};
  std::atomic<bool> ipv6_native_ready_{false}, ipv6_native_link_{false}, ipv6_ready_{false}, ipv6_path_ready_{false};
  std::atomic<bool> ipv6_mac_ready_{false};
  std::atomic<uint32_t> ipv6_grant_refreshed_{0};
  uint32_t ipv6_local_generation_{1}, ipv6_gateway_generation_{0};
  Ipv6AddressSnapshot ipv6_previous_local_{};
  uint32_t ipv6_saved_valid_life_[Ipv6AddressSnapshot::CAPACITY]{};
  uint32_t ipv6_saved_pref_life_[Ipv6AddressSnapshot::CAPACITY]{};
  uint32_t ipv6_lifetime_saved_{0}, ipv6_last_rs_{0};
  uint32_t ipv6_last_native_announcement_{0};
  uint8_t ipv6_native_announcements_{0};
  bool ipv6_was_native_{false}, ipv6_initialized_{false};
  netif_output_ip6_fn original_station_output_ipv6_{nullptr};
#endif

  uint8_t node_id_{0};
  bool require_dhcp_{false};
  uint16_t gateway_candidates_{0};
  std::atomic<uint8_t> gateway_id_{0};
  std::atomic<uint32_t> gateway_generation_{2}, applied_generation_{0};
  std::atomic<bool> gateway_enabled_{true};
  struct IdentityRequest {
    std::atomic<uint32_t> low{0}, high{0}, epoch{0}, applied{0}, revision{0};
  };
  IdentityRequest identity_requests_[mesh_limits::MAX_NODES]{};
  std::atomic<uint16_t> identity_pending_mask_{0};
  // Validated leases are tied to a gateway epoch. A handover retains the IP
  // without allowing ordinary traffic before the new gateway proves ownership.
  std::atomic<bool> mesh_path_validated_{true};
  struct netif virtual_netif_ {};
  struct netif *station_netif_{nullptr};  // Selected native LAN interface, Wi-Fi or Ethernet.
#ifndef MESH_IP_CLIENT_ONLY
  netif_input_fn original_station_input_{nullptr};
  netif_output_fn original_station_output_{nullptr};
#endif
  bool virtual_added_{false};
  bool previous_station_connected_{false};
  uint32_t station_announcement_start_{0}, last_station_announcement_{0};
  std::atomic<bool> configured_{false}, ready_{false}, pending_{false}, available_{false}, fallback_active_{false};
  std::atomic<bool> station_connected_{false}, mesh_reachable_{false};
  std::atomic<bool> mesh_lease_{false};
  std::atomic<uint32_t> address_{0}, mask_{0}, gateway_{0};
#ifndef MESH_IP_CLIENT_ONLY
  Peer peers_[mesh_limits::MAX_NODES]{};
  DhcpTransaction dhcp_transactions_[mesh_limits::MAX_NODES]{};
  LeaseProbe lease_probes_[mesh_limits::MAX_NODES]{};
  DhcpOwnership dhcp_ownership_[mesh_limits::MAX_NODES]{};
  RemoteWitness remote_witnesses_[mesh_limits::MAX_NODES]{};
  // DHCP ages use the SDK's monotonic 64-bit uptime, reduced to seconds. No
  // lease is multiplied into a wrapping millisecond deadline or mixed snapshot.
  struct PeerMac {
    std::atomic<uint32_t> low{0}, high{0};
  };
  PeerMac dhcp_peer_macs_[mesh_limits::MAX_NODES]{};
  std::atomic<uint16_t> dhcp_peer_mac_mask_{0};
#endif
  StaticQueue_t rx_storage_{};
  IpFlowQueue tx_flows_;
  portMUX_TYPE tx_lock_ = portMUX_INITIALIZER_UNLOCKED;
  void *transport_wake_context_{nullptr};
  void (*transport_wake_)(void *){nullptr};
#ifndef MESH_IP_CLIENT_ONLY
  StaticQueue_t arp_storage_{}, probe_request_storage_{}, probe_result_storage_{};
#endif
  uint8_t rx_buffer_[RX_CAPACITY * sizeof(IpPacket)]{};
  QueueHandle_t rx_queue_{nullptr};
  bool rx_pending_{false};
#ifndef MESH_IP_CLIENT_ONLY
  uint8_t arp_buffer_[ARP_CAPACITY * sizeof(ArpRequest)]{};
  uint8_t probe_request_buffer_[PROBE_QUEUE_CAPACITY * sizeof(LeaseProbeResult)]{};
  uint8_t probe_result_buffer_[PROBE_QUEUE_CAPACITY * sizeof(LeaseProbeResult)]{};
  QueueHandle_t arp_queue_{nullptr};
  QueueHandle_t probe_request_queue_{nullptr}, probe_result_queue_{nullptr};
#endif
  // RX keeps accepted packets across lwIP backpressure; synchronous ACK/RST
  // output writes directly into its own reserved TX slot, without sharing RX.
  IpPacket tcpip_rx_packet_{};
#ifndef MESH_IP_CLIENT_ONLY
  // The driver and TCP/IP DHCP state writers share this nonblocking guard.
  // It remains necessary even though the driver no longer has a TX scratch.
  std::atomic<bool> driver_tx_busy_{false};
#endif
  std::atomic<uint32_t> tcpip_stack_min_{UINT32_MAX};
  std::atomic<uint32_t> flow_backpressure_{0}, rx_retries_{0};
  std::atomic<uint32_t> mesh_tx_{0}, mesh_rx_{0}, queue_drops_{0}, invalid_packets_{0}, proxy_arp_{0}, lan_tx_{0};
};

}  // namespace mesh_ip
