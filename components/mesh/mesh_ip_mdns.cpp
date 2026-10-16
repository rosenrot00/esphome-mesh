#include "mesh_ip_mdns.h"
#ifdef USE_MESH_DISCOVERY
#include "esphome/core/application.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include <mdns.h>
#include <cstring>

namespace esphome::mesh {
#ifndef MESH_IP_CLIENT_ONLY
static const char *const TAG = "mesh.mdns";
#endif

void MeshIpMdns::setup() {
#ifndef MESH_IP_CLIENT_ONLY
  this->queue_ = xQueueCreateStatic(8, sizeof(Chunk), this->queue_buffer_, &this->queue_storage_);
#endif
}
bool MeshIpMdns::update_peer_identity(uint8_t node, const uint8_t *mac, uint32_t identity_epoch) {
  if (node == 0 || node > mesh_limits::MAX_NODES || identity_epoch == 0)
    return false;
  uint32_t low = 0, high = 0;
  if (mac != nullptr) {
    if ((mac[0] & 1) != 0)
      return false;
    std::memcpy(&low, mac, 4);
    std::memcpy(&high, mac + 4, 2);
    if (low == 0 && high == 0)
      return false;
  }
#ifdef MESH_IP_CLIENT_ONLY
  return true;  // A client build owns no delegated hostname or peer registry.
#else
  auto &request = this->identities_[node - 1];
  if (request.epoch.load() == identity_epoch) {
    if (request.low.load() != low || request.high.load() != high)
      return false;
    return request.applied.load() == identity_epoch;
  }
  request.generation.fetch_add(1);
  // Worker is the sole status writer. Fence old queued metadata and clear the
  // latest status before the main loop can authorize a replacement owner.
  auto &status = this->statuses_[node - 1];
  status.epoch.fetch_add(1);
  status.generation.fetch_add(1);
  status.address.store(0);
  status.seen.store(0);
#ifdef MESH_IPV6
  status.ipv6_active.store(false);
  status.ipv6_seen.store(0);
#endif
  status.generation.fetch_add(1);
  request.low.store(low);
  request.high.store(high);
  request.epoch.store(identity_epoch);
  request.generation.fetch_add(1);
  return false;
#endif
}
#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpMdns::identity_current_(uint8_t node) const {
  const auto &request = this->identities_[node - 1];
  const uint32_t generation = request.generation.load();
  return (generation & 1) == 0 && request.epoch.load() == request.applied.load() &&
         request.generation.load() == generation;
}
void MeshIpMdns::apply_identity_changes_() {
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    auto &request = this->identities_[node - 1];
    const uint32_t generation = request.generation.load();
    const uint32_t epoch = request.epoch.load();
    if ((generation & 1) != 0 || epoch == request.applied.load())
      continue;
    uint8_t mac[6]{};
    const uint32_t low = request.low.load(), high = request.high.load();
    std::memcpy(mac, &low, 4);
    std::memcpy(mac + 4, &high, 2);
    if (request.generation.load() != generation)
      continue;
    // An unavailable responder can still retire an unpublished registry slot.
    // Actual delegated ownership must wait for real asynchronous SDK removal.
    if (this->records_[node - 1].hostname[0] != 0 && (!this->ready_() || !this->withdraw_(node)))
      continue;
    this->registry_.revoke(node);
    if (low != 0 || high != 0)
      this->registry_.authorize(node, mac);
    this->retry_after_[node - 1] = 0;
    auto &status = this->statuses_[node - 1];
    status.consumed_epoch = status.epoch.load();
    status.consumed = status.generation.load();
    if (request.generation.load() == generation)
      request.applied.store(epoch);
  }
}
#endif
bool MeshIpMdns::ready_() const {
  if (this->component_ == nullptr || this->component_->is_failed())
    return false;
  char hostname[MDNS_NAME_BUF_LEN]{};
  return mdns_hostname_get(hostname) == ESP_OK;
}
bool MeshIpMdns::local_descriptor(uint8_t *output, size_t capacity, size_t &written) {
#ifdef MESH_IP_GATEWAY_ONLY
  (void) output;
  (void) capacity;
  written = 0;
  return false;
#else
  written = 0;
  if (!this->ready_())
    return false;
  ::mesh_ip::DiscoveryDescriptor descriptor;
  if (!descriptor.set_hostname(App.get_name().c_str()))
    return false;
  for (const auto &service : this->component_->get_services()) {
    const auto *type = MDNS_STR_ARG(service.service_type);
    if (std::strcmp(MDNS_STR_ARG(service.proto), "_tcp") != 0)
      continue;
    if (std::strcmp(type, "_esphomelib") == 0) {
      descriptor.api_port = service.port.value();
      for (const auto &txt : service.txt_records)
        if (!descriptor.add_txt(MDNS_STR_ARG(txt.key), MDNS_STR_ARG(txt.value)))
          return false;
    } else if (std::strcmp(type, "_http") == 0) {
      descriptor.http_port = service.port.value();
    }
  }
  return ::mesh_ip::encode_discovery(descriptor, output, capacity, written);
#endif
}
void MeshIpMdns::enqueue(uint8_t node, const uint8_t *data, size_t length) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node;
  (void) data;
  (void) length;
#else
  if (this->queue_ == nullptr || node == 0 || node > mesh_limits::MAX_NODES || data == nullptr ||
      length > sizeof(Chunk::data))
    return;
  if (!this->identity_current_(node))
    return;
  Chunk chunk;
  chunk.node = node;
  chunk.length = length;
  chunk.epoch = this->statuses_[node - 1].epoch.load();
  std::memcpy(chunk.data, data, length);
  if (xQueueSend(this->queue_, &chunk, 0) != pdTRUE)
    ESP_LOGW(TAG, "Discovery metadata queue full; node will refresh");
#endif
}

void MeshIpMdns::note_status(uint8_t node, uint32_t address, bool fallback) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node;
  (void) address;
  (void) fallback;
#else
  if (node == 0 || node > mesh_limits::MAX_NODES)
    return;
  if (!this->identity_current_(node))
    return;
  auto &status = this->statuses_[node - 1];
  if (!fallback
#ifdef MESH_IPV6
      && !status.ipv6_active.load()
#endif
  )
    status.epoch.fetch_add(1);
  // The worker is the sole writer; the main loop reads a coherent snapshot
  // without taking its transport mutex or delaying OTA forwarding.
  status.generation.fetch_add(1);
  status.address.store(fallback ? address : 0);
  status.seen.store(millis());
  status.generation.fetch_add(1);
#endif
}

#ifdef MESH_IPV6
void MeshIpMdns::note_ipv6_status(uint8_t node, const ::mesh_ip::Ipv6AddressSnapshot &snapshot) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) node;
  (void) snapshot;
#else
  if (node == 0 || node > mesh_limits::MAX_NODES || !this->identity_current_(node))
    return;
  auto &status = this->statuses_[node - 1];
  const bool active = snapshot.ready && snapshot.count != 0;
  if (status.ipv6_active.exchange(active) && !active && status.address.load() == 0)
    status.epoch.fetch_add(1);
  status.ipv6_seen.store(millis());
#endif
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
bool MeshIpMdns::withdraw_(uint8_t node) {
  auto &record = this->records_[node - 1];
  if (record.hostname[0] == 0) {
    this->published_[node - 1].store(false);
    return true;
  }
  // ESP-IDF service removal transmits PTR TTL=0 before deleting the record.
  // Cached A/SRV/TXT retain their normal TTL; no further answers are emitted.
  // Leave published=true on a failure so a handover cannot ACK prematurely.
  if (record.api) {
    const auto err =
        mdns_service_remove_for_host(record.hostname.data(), "_esphomelib", "_tcp", record.hostname.data());
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND)
      return false;
    record.api = false;
  }
  if (record.http) {
    const auto err = mdns_service_remove_for_host(record.hostname.data(), "_http", "_tcp", record.hostname.data());
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND)
      return false;
    record.http = false;
  }
  if (!record.removal_pending) {
    const auto err = mdns_delegate_hostname_remove(record.hostname.data());
    if (err != ESP_OK)
      return false;
    record.removal_pending = true;
  }
  // Host removal is asynchronous in ESP-IDF. Do not acknowledge a handover
  // until the responder really stopped owning the delegated A record too.
  if (mdns_hostname_exists(record.hostname.data()))
    return false;
  ESP_LOGI(TAG, "DISCOVERY withdraw node=%u host=%s.local", node, record.hostname.data());
  record = Published{};
  this->published_[node - 1].store(false);
  return true;
}
#endif

#ifndef MESH_IP_CLIENT_ONLY
#ifdef MESH_IPV6
bool MeshIpMdns::collect_ipv6_(uint8_t node, ::mesh_ip::MeshIpNetif &netif,
                               ::mesh_ip::Ipv6AddressSnapshot &snapshot) const {
  if (!netif.peer_ipv6_snapshot(node, snapshot) || !snapshot.ready || snapshot.count == 0 ||
      snapshot.count > ::mesh_ip::Ipv6AddressSnapshot::CAPACITY) {
    snapshot = {};
    return false;
  }
  for (size_t i = 0; i < snapshot.count; ++i) {
    if (!netif.peer_ipv6_address_valid(node, snapshot.addresses[i])) {
      snapshot = {};
      return false;
    }
  }
  return true;
}
#endif
bool MeshIpMdns::publish_(uint8_t node, uint32_t address, const ::mesh_ip::DiscoveryDescriptor &descriptor,
                          ::mesh_ip::MeshIpNetif &netif) {
  if (!this->identity_current_(node))
    return false;
  if (descriptor.hostname() == App.get_name().c_str() || mdns_hostname_exists(descriptor.hostname().data())) {
    ESP_LOGW(TAG, "Discovery hostname already owned: %s", descriptor.hostname().data());
    return false;
  }
  mdns_ip_addr_t ips[1
#ifdef MESH_IPV6
                     + ::mesh_ip::Ipv6AddressSnapshot::CAPACITY
#endif
  ]{};
  size_t count = 0;
  if (address != 0) {
    ips[count].addr.type = ESP_IPADDR_TYPE_V4;
    ips[count++].addr.u_addr.ip4.addr = address;
  }
#ifdef MESH_IPV6
  ::mesh_ip::Ipv6AddressSnapshot ipv6;
  this->collect_ipv6_(node, netif, ipv6);
  for (size_t i = 0; i < ipv6.count; ++i) {
    ips[count].addr.type = ESP_IPADDR_TYPE_V6;
    std::memcpy(ips[count++].addr.u_addr.ip6.addr, ipv6.addresses[i].bytes.data(), 16);
  }
#endif
  if (count == 0)
    return false;
  for (size_t i = 1; i < count; ++i)
    ips[i - 1].next = &ips[i];
  // Claim before the final ownership check. If a quiet heartbeat raced this
  // main-loop pass, either the worker already ACKed and we see address=0, or
  // it sees published=true and waits for our goodbye. Never publish after ACK.
  this->published_[node - 1].store(true);
  bool owned = netif.peer_mesh_address(node) == address;
#ifdef MESH_IPV6
  for (size_t i = 0; i < ipv6.count; ++i)
    owned &= netif.peer_ipv6_address_valid(node, ipv6.addresses[i]);
#endif
  if (!owned) {
    this->published_[node - 1].store(false);
    return false;
  }
  if (mdns_delegate_hostname_add(descriptor.hostname().data(), ips) != ESP_OK ||
      !mdns_hostname_exists(descriptor.hostname().data())) {
    this->published_[node - 1].store(false);
    return false;
  }
  auto &record = this->records_[node - 1];
  const auto hostname = descriptor.hostname();
  std::memcpy(record.hostname.data(), hostname.data(), hostname.size());
  record.hostname[hostname.size()] = 0;
  record.address = address;
#ifdef MESH_IPV6
  record.ipv6 = ipv6;
#endif
  record.revision = this->registry_.revision(node);
  // Mark partial registration as owned too; its removal must precede handover.
  std::array<mdns_txt_item_t, ::mesh_ip::DISCOVERY_TXT_MAX> txt{};
  for (size_t i = 0; i < descriptor.txt_count(); ++i) {
    const auto item = descriptor.txt(i);
    txt[i] = {item.key.data(), item.value.data()};
  }
  auto err =
      mdns_service_add_for_host(descriptor.hostname().data(), "_esphomelib", "_tcp", descriptor.hostname().data(),
                                descriptor.api_port, txt.data(), descriptor.txt_count());
  if (err == ESP_OK)
    record.api = true;
  if (err == ESP_OK && descriptor.http_port != 0) {
    err = mdns_service_add_for_host(descriptor.hostname().data(), "_http", "_tcp", descriptor.hostname().data(),
                                    descriptor.http_port, nullptr, 0);
    if (err == ESP_OK)
      record.http = true;
  }
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Discovery registration failed: %s", esp_err_to_name(err));
    this->withdraw_(node);
    return false;
  }
  ESP_LOGI(TAG, "DISCOVERY publish node=%u host=%s.local api=%u", node, descriptor.hostname().data(),
           descriptor.api_port);
  return true;
}
#endif

void MeshIpMdns::loop(::mesh_ip::MeshIpNetif &netif, bool gateway) {
#ifdef MESH_IP_CLIENT_ONLY
  (void) netif;
  (void) gateway;
#else
  uint32_t now = millis();
  if (uint32_t(now - this->last_loop_) < 50)
    return;
  this->last_loop_ = now;
  this->apply_identity_changes_();
  if (!gateway) {
    // Gateway selection runs in the worker, while SDK ownership changes run
    // here. A demoted candidate must send its goodbyes even when it no longer
    // receives peer traffic. Never retain metadata for a later re-promotion.
    for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
      auto &status = this->statuses_[node - 1];
      this->registry_.forget(node);
      status.consumed_epoch = status.epoch.fetch_add(1) + 1;
      status.consumed = status.generation.load();
      this->retry_after_[node - 1] = 0;
    }
    Chunk chunk;
    while (this->queue_ != nullptr && xQueueReceive(this->queue_, &chunk, 0) == pdTRUE) {
    }
    // Retain published ownership until asynchronous host removal completes.
    // If mDNS is temporarily unavailable, the next pass retries withdrawal;
    // the invalidated queue and registry stay invalid in the meantime.
    if (this->ready_())
      for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++)
        this->withdraw_(node);
    return;
  }
  if (!this->ready_())
    return;
  // Preserve a quiet/direct ownership gap even if a later fallback heartbeat
  // arrived before the main loop could observe the intermediate state.
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
    auto &status = this->statuses_[node - 1];
    const uint32_t epoch = status.epoch.load();
    if (epoch != status.consumed_epoch) {
      this->registry_.forget(node);
      status.consumed_epoch = epoch;
    }
  }
  Chunk chunk;
  while (xQueueReceive(this->queue_, &chunk, 0) == pdTRUE)
    if (chunk.node >= 1 && chunk.node <= mesh_limits::MAX_NODES && this->identity_current_(chunk.node) &&
        chunk.epoch == this->statuses_[chunk.node - 1].epoch.load())
      this->registry_.receive(chunk.node, chunk.data, chunk.length, now);
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
    if (!this->identity_current_(node))
      continue;
    auto &status = this->statuses_[node - 1];
    const uint32_t generation = status.generation.load();
    if ((generation & 1) != 0 || generation == status.consumed)
      continue;
    const uint32_t address = status.address.load(), seen = status.seen.load();
    if (status.generation.load() != generation)
      continue;
    status.consumed = generation;
    if (address != 0 && uint32_t(millis() - seen) < 5000 && netif.peer_mesh_address(node) == address)
      this->registry_.refresh(node, address, seen);
  }
#ifdef MESH_IPV6
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; ++node) {
    if (!this->identity_current_(node))
      continue;
    auto &status = this->statuses_[node - 1];
    const uint32_t seen = status.ipv6_seen.load();
    ::mesh_ip::Ipv6AddressSnapshot ipv6;
    if (!status.ipv6_active.load() || uint32_t(millis() - seen) >= 5000 || !this->collect_ipv6_(node, netif, ipv6))
      continue;
    for (size_t i = 0; i < ipv6.count; ++i)
      this->registry_.refresh(node, ipv6.addresses[i], seen);
  }
#endif
  // The worker can publish a newer heartbeat while this main-loop pass drains
  // metadata. Never expire that timestamp using an older captured clock value.
  now = millis();
  this->registry_.expire(now);
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++) {
    const uint32_t address = netif.peer_mesh_address(node);
#ifdef MESH_IPV6
    ::mesh_ip::Ipv6AddressSnapshot ipv6;
    this->collect_ipv6_(node, netif, ipv6);
#endif
    // A reboot/OTA may acquire the same DHCP address with different metadata.
    // Never reuse the preceding firmware's descriptor across an ownership gap.
    if (address == 0
#ifdef MESH_IPV6
        && ipv6.count == 0
#endif
    )
      this->registry_.forget(node);
    const ::mesh_ip::DiscoveryDescriptor *descriptor = nullptr;
    if (this->identity_current_(node)) {
      descriptor = this->registry_.current(node, address, now);
#ifdef MESH_IPV6
      for (size_t i = 0; descriptor == nullptr && i < ipv6.count; ++i)
        descriptor = this->registry_.current(node, ipv6.addresses[i], now);
#endif
    }
    auto &record = this->records_[node - 1];
    bool address_changed = record.address != address;
#ifdef MESH_IPV6
    address_changed |= record.ipv6.count != ipv6.count;
    for (size_t i = 0; i < ipv6.count; ++i)
      address_changed |= record.ipv6.addresses[i] != ipv6.addresses[i];
#endif
    if (record.hostname[0] != 0 && (record.removal_pending || descriptor == nullptr || address_changed ||
                                    record.revision != this->registry_.revision(node))) {
      if (!record.removal_pending)
        ESP_LOGI(TAG, "DISCOVERY unavailable node=%u reason=%s", node,
                 address == 0 ? "ownership" : (descriptor == nullptr ? "metadata_expired" : "metadata_changed"));
      if (!this->withdraw_(node))
        continue;
    }
    if (descriptor && record.hostname[0] == 0 && uint32_t(now - this->retry_after_[node - 1]) >= 1000) {
      this->retry_after_[node - 1] = now;
      this->publish_(node, address, *descriptor, netif);
    }
  }
#endif
}
void MeshIpMdns::shutdown() {
#ifndef MESH_IP_CLIENT_ONLY
  if (!this->ready_())
    return;
  for (uint8_t node = 1; node <= mesh_limits::MAX_NODES; node++)
    this->withdraw_(node);
#endif
}
}  // namespace esphome::mesh
#endif
