#include "mesh_ip_discovery.h"

#include <cstring>

namespace mesh_ip {
namespace {
bool valid_hostname(std::string_view name) {
  if (name.empty() || name.size() > 63 || name.front() == '-' || name.back() == '-')
    return false;
  for (const unsigned char c : name)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
      return false;
  return true;
}
bool valid_items(std::string_view hostname, uint16_t api_port, const DiscoveryTxt *items, size_t count) {
  if (!valid_hostname(hostname) || api_port == 0 || count > DISCOVERY_TXT_MAX)
    return false;
  bool mac = false;
  for (size_t i = 0; i < count; ++i) {
    const auto &item = items[i];
    if (item.key.empty() || item.key.size() > 63 || item.key.size() + 1 + item.value.size() > 255 ||
        item.value.find('\0') != std::string_view::npos)
      return false;
    for (const unsigned char c : item.key)
      if (c < 0x21 || c > 0x7e || c == '=')
        return false;
    for (size_t j = 0; j < i; ++j)
      if (items[j].key == item.key)
        return false;
    if (item.key == "mac") {
      if (item.value.size() != 12)
        return false;
      for (const unsigned char c : item.value)
        if (!((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')))
          return false;
      mac = true;
    }
  }
  return mac;
}
struct DescriptorView {
  std::string_view hostname;
  uint16_t api_port{0}, http_port{0};
  size_t count{0};
  std::array<DiscoveryTxt, DISCOVERY_TXT_MAX> items{};
};
bool valid_descriptor(const DiscoveryDescriptor &descriptor) {
  DescriptorView view;
  for (size_t i = 0; i < descriptor.txt_count(); ++i)
    view.items[i] = descriptor.txt(i);
  return descriptor.storage_valid() &&
         valid_items(descriptor.hostname(), descriptor.api_port, view.items.data(), descriptor.txt_count());
}
uint16_t read16(const uint8_t *p) { return uint16_t(p[0]) | uint16_t(p[1]) << 8; }
void write16(uint8_t *p, uint16_t value) {
  p[0] = value & 255;
  p[1] = value >> 8;
}
uint32_t read32(const uint8_t *p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
void write32(uint8_t *p, uint32_t value) {
  for (size_t i = 0; i < 4; i++)
    p[i] = value >> (8 * i);
}
}  // namespace

bool DiscoveryAddress::valid() const {
#ifdef MESH_IPV6
  if (this->is_ipv6)
    return !this->ipv6.unspecified() && !this->ipv6.multicast();
#endif
  return this->ipv4 != 0;
}
bool DiscoveryAddress::operator==(const DiscoveryAddress &other) const {
#ifdef MESH_IPV6
  if (this->is_ipv6 != other.is_ipv6)
    return false;
  if (this->is_ipv6)
    return this->ipv6 == other.ipv6;
#endif
  return this->ipv4 == other.ipv4;
}

namespace {
bool parse_descriptor(const uint8_t *data, size_t length, DescriptorView &view) {
  if (data == nullptr || length < 8 || length > DISCOVERY_DESCRIPTOR_MAX || data[0] != 1)
    return false;
  size_t cursor = 2;
  const size_t name_length = data[1];
  if (name_length > 63 || cursor + name_length + 5 > length)
    return false;
  view.hostname = {reinterpret_cast<const char *>(data + cursor), name_length};
  cursor += name_length;
  view.api_port = read16(data + cursor);
  cursor += 2;
  view.http_port = read16(data + cursor);
  cursor += 2;
  view.count = data[cursor++];
  if (view.count > DISCOVERY_TXT_MAX)
    return false;
  for (size_t i = 0; i < view.count; ++i) {
    if (cursor + 2 > length)
      return false;
    const size_t key_length = data[cursor++], value_length = data[cursor++];
    if (cursor + key_length + value_length > length)
      return false;
    view.items[i].key = {reinterpret_cast<const char *>(data + cursor), key_length};
    cursor += key_length;
    view.items[i].value = {reinterpret_cast<const char *>(data + cursor), value_length};
    cursor += value_length;
  }
  return cursor == length && valid_items(view.hostname, view.api_port, view.items.data(), view.count);
}
void assign_descriptor(const DescriptorView &view, DiscoveryDescriptor &descriptor) {
  // Validation established wire length<=768. Packed text needs wire length-6,
  // including every terminator, so these bounded appends cannot fail.
  descriptor.clear();
  descriptor.set_hostname(view.hostname);
  descriptor.api_port = view.api_port;
  descriptor.http_port = view.http_port;
  for (size_t i = 0; i < view.count; ++i)
    descriptor.add_txt(view.items[i].key, view.items[i].value);
}
}  // namespace

DiscoveryDescriptor::DiscoveryDescriptor(std::string_view hostname, uint16_t api, uint16_t http,
                                         std::initializer_list<DiscoveryTxt> txt) {
  this->set_hostname(hostname);
  this->api_port = api;
  this->http_port = http;
  for (const auto &item : txt)
    this->add_txt(item.key, item.value);
}
void DiscoveryDescriptor::clear() {
  this->api_port = this->http_port = 0;
  this->used_ = 1;
  this->hostname_length_ = this->txt_count_ = 0;
  this->storage_valid_ = true;
  this->text_[0] = 0;
}
DiscoveryTxt DiscoveryDescriptor::txt(size_t index) const {
  if (index >= this->txt_count_)
    return {};
  const auto &entry = this->txt_[index];
  return {{this->text_.data() + entry.key, entry.key_length}, {this->text_.data() + entry.value, entry.value_length}};
}
bool DiscoveryDescriptor::replace_text_(uint16_t offset, uint8_t previous_length, std::string_view value) {
  if (value.size() > 255) {
    this->storage_valid_ = false;
    return false;
  }
  const int delta = int(value.size()) - previous_length;
  if (int(this->used_) + delta > int(this->text_.size())) {
    this->storage_valid_ = false;
    return false;
  }
  char copy[256];
  if (!value.empty())
    std::memmove(copy, value.data(), value.size());
  const size_t tail = offset + previous_length + 1;
  std::memmove(this->text_.data() + int(tail) + delta, this->text_.data() + tail, this->used_ - tail);
  if (!value.empty())
    std::memcpy(this->text_.data() + offset, copy, value.size());
  this->text_[offset + value.size()] = 0;
  this->used_ = uint16_t(int(this->used_) + delta);
  for (size_t i = 0; i < this->txt_count_; ++i) {
    if (this->txt_[i].key > offset)
      this->txt_[i].key = uint16_t(int(this->txt_[i].key) + delta);
    if (this->txt_[i].value > offset)
      this->txt_[i].value = uint16_t(int(this->txt_[i].value) + delta);
  }
  return true;
}
bool DiscoveryDescriptor::set_hostname(std::string_view hostname) {
  if (hostname.size() > 63) {
    this->storage_valid_ = false;
    return false;
  }
  if (!this->replace_text_(0, this->hostname_length_, hostname))
    return false;
  this->hostname_length_ = uint8_t(hostname.size());
  return true;
}
bool DiscoveryDescriptor::add_txt(std::string_view key, std::string_view value) {
  if (this->txt_count_ == DISCOVERY_TXT_MAX || key.size() > 63 || value.size() > 255 ||
      key.size() + value.size() + 2 > this->text_.size() - this->used_) {
    this->storage_valid_ = false;
    return false;
  }
  auto &entry = this->txt_[this->txt_count_++];
  entry.key = this->used_;
  entry.key_length = uint8_t(key.size());
  if (!key.empty())
    std::memmove(this->text_.data() + this->used_, key.data(), key.size());
  this->used_ += key.size();
  this->text_[this->used_++] = 0;
  entry.value = this->used_;
  entry.value_length = uint8_t(value.size());
  if (!value.empty())
    std::memmove(this->text_.data() + this->used_, value.data(), value.size());
  this->used_ += value.size();
  this->text_[this->used_++] = 0;
  return true;
}
bool DiscoveryDescriptor::set_txt_value(size_t index, std::string_view value) {
  if (index >= this->txt_count_)
    return false;
  auto &entry = this->txt_[index];
  if (!this->replace_text_(entry.value, entry.value_length, value))
    return false;
  entry.value_length = uint8_t(value.size());
  return true;
}

bool encode_discovery(const DiscoveryDescriptor &descriptor, uint8_t *output, size_t capacity, size_t &written) {
  written = 0;
  if (output == nullptr || !valid_descriptor(descriptor))
    return false;
  const auto hostname = descriptor.hostname();
  size_t required = 7 + hostname.size();
  for (size_t i = 0; i < descriptor.txt_count(); ++i) {
    const auto txt = descriptor.txt(i);
    required += 2 + txt.key.size() + txt.value.size();
  }
  if (required > DISCOVERY_DESCRIPTOR_MAX || required > capacity)
    return false;
  output[written++] = 1;
  output[written++] = hostname.size();
  std::memcpy(output + written, hostname.data(), hostname.size());
  written += hostname.size();
  write16(output + written, descriptor.api_port);
  written += 2;
  write16(output + written, descriptor.http_port);
  written += 2;
  output[written++] = descriptor.txt_count();
  for (size_t i = 0; i < descriptor.txt_count(); ++i) {
    const auto txt = descriptor.txt(i);
    output[written++] = txt.key.size();
    output[written++] = txt.value.size();
    std::memcpy(output + written, txt.key.data(), txt.key.size());
    written += txt.key.size();
    if (!txt.value.empty())
      std::memcpy(output + written, txt.value.data(), txt.value.size());
    written += txt.value.size();
  }
  return true;
}
bool decode_discovery(const uint8_t *data, size_t length, DiscoveryDescriptor &descriptor) {
  DescriptorView view;
  if (!parse_descriptor(data, length, view))
    return false;
  assign_descriptor(view, descriptor);
  return true;
}

uint32_t discovery_digest(const uint8_t *data, size_t length) {
  uint32_t digest = 0xffffffffU;
  for (size_t i = 0; i < length; i++) {
    digest ^= data[i];
    for (size_t bit = 0; bit < 8; bit++)
      digest = (digest >> 1) ^ ((digest & 1) ? 0xedb88320U : 0);
  }
  return ~digest;
}

bool discovery_chunk(const uint8_t *data, size_t length, uint32_t address, size_t offset, uint8_t *output,
                     size_t capacity, size_t &written, size_t payload_budget) {
  written = 0;
  if (payload_budget < DISCOVERY_FRAME_MIN || payload_budget > DISCOVERY_FRAME_MAX)
    return false;
  const size_t stride = payload_budget - DISCOVERY_HEADER_SIZE;
  if (data == nullptr || output == nullptr || length == 0 || length > DISCOVERY_DESCRIPTOR_MAX || address == 0 ||
      offset >= length || offset % stride != 0)
    return false;
  const size_t count = length - offset < stride ? length - offset : stride;
  if (capacity < DISCOVERY_HEADER_SIZE + count)
    return false;
  // The default encoding remains byte-for-byte v1. The v2 extension declares
  // the stride, so a receiver never infers offsets from its own link's MTU.
  output[0] = payload_budget == DISCOVERY_FRAME_MAX ? 1 : 2;
  output[1] = DISCOVERY_CONTROL;
  std::memcpy(output + 2, &address, 4);
  write32(output + 6, discovery_digest(data, length));
  write16(output + 10, length);
  write16(output + 12, offset);
  output[14] = output[0] == 1 ? 0 : stride;
  output[15] = 0;
  std::memcpy(output + DISCOVERY_HEADER_SIZE, data + offset, count);
  written = DISCOVERY_HEADER_SIZE + count;
  return true;
}

#ifdef MESH_IPV6
bool discovery_chunk(const uint8_t *data, size_t length, const Ipv6Address &address, size_t offset, uint8_t *output,
                     size_t capacity, size_t &written, size_t payload_budget) {
  written = 0;
  if (payload_budget < DISCOVERY_IPV6_FRAME_MIN || payload_budget > DISCOVERY_FRAME_MAX)
    return false;
  const size_t stride = payload_budget - DISCOVERY_IPV6_HEADER_SIZE;
  if (data == nullptr || output == nullptr || length == 0 || length > DISCOVERY_DESCRIPTOR_MAX ||
      !DiscoveryAddress(address).valid() || offset >= length || offset % stride != 0)
    return false;
  const size_t count = length - offset < stride ? length - offset : stride;
  if (capacity < DISCOVERY_IPV6_HEADER_SIZE + count)
    return false;
  output[0] = 3;
  output[1] = DISCOVERY_CONTROL;
  std::memcpy(output + 2, address.bytes.data(), 16);
  write32(output + 18, discovery_digest(data, length));
  write16(output + 22, length);
  write16(output + 24, offset);
  output[26] = static_cast<uint8_t>(stride);
  output[27] = 0;
  std::memcpy(output + DISCOVERY_IPV6_HEADER_SIZE, data + offset, count);
  written = DISCOVERY_IPV6_HEADER_SIZE + count;
  return true;
}
#endif

DiscoveryRegistry::Assembly *DiscoveryRegistry::assembly_(uint8_t node) {
  for (auto &assembly : this->assemblies_)
    if (assembly.owner == node)
      return &assembly;
  return nullptr;
}

void DiscoveryRegistry::clear_assembly_(uint8_t node) {
  this->waiting_ &= uint16_t(~(uint16_t(1) << (node - 1)));
  if (auto *assembly = this->assembly_(node)) {
    assembly->owner = 0;
    assembly->active = false;
  }
}

void DiscoveryRegistry::expire_assemblies_(uint32_t now) {
  for (auto &assembly : this->assemblies_)
    if (assembly.owner != 0 && uint32_t(now - assembly.started) >= 2000) {
      assembly.owner = 0;
      assembly.active = false;
    }
}

void DiscoveryRegistry::admit_waiters_(uint32_t now) {
  for (auto &assembly : this->assemblies_) {
    if (assembly.owner != 0)
      continue;
    for (size_t visited = 0; visited < mesh_limits::MAX_NODES; ++visited) {
      const uint8_t index = this->admission_cursor_;
      this->admission_cursor_ = (index + 1) % mesh_limits::MAX_NODES;
      const uint16_t bit = uint16_t(1) << index;
      if ((this->waiting_ & bit) == 0)
        continue;
      this->waiting_ &= uint16_t(~bit);
      if (!this->peers_[index].authorized)
        continue;
      assembly.owner = index + 1;
      assembly.active = false;
      assembly.chunks = 0;
      assembly.started = now;
      break;
    }
  }
}

bool DiscoveryRegistry::authorize(uint8_t node, const uint8_t *mac) {
  if (node == 0 || node > mesh_limits::MAX_NODES || mac == nullptr || (mac[0] & 1))
    return false;
  uint8_t any = 0;
  for (size_t i = 0; i < 6; i++)
    any |= mac[i];
  if (!any)
    return false;
  auto &peer = this->peers_[node - 1];
  this->clear_assembly_(node);
  peer.descriptor_valid = false;
  peer.descriptor.clear();
  peer.address = {};
  peer.digest = peer.seen = peer.revision = 0;
  std::memcpy(peer.mac, mac, 6);
  peer.authorized = true;
  return true;
}

void DiscoveryRegistry::revoke(uint8_t node) {
  if (node < 1 || node > mesh_limits::MAX_NODES)
    return;
  auto &peer = this->peers_[node - 1];
  this->clear_assembly_(node);
  peer.authorized = peer.descriptor_valid = false;
  peer.descriptor.clear();
  peer.address = {};
  peer.digest = peer.seen = peer.revision = 0;
}

bool DiscoveryRegistry::receive(uint8_t node, const uint8_t *data, size_t length, uint32_t now) {
  if (node == 0 || node > mesh_limits::MAX_NODES || !this->peers_[node - 1].authorized || data == nullptr ||
      length <= DISCOVERY_HEADER_SIZE || length > DISCOVERY_FRAME_MAX || data[1] != DISCOVERY_CONTROL)
    return false;
  size_t stride, header = DISCOVERY_HEADER_SIZE, digest_offset = 6;
  DiscoveryAddress address;
#ifdef MESH_IPV6
  if (data[0] == 3) {
    if (length <= DISCOVERY_IPV6_HEADER_SIZE || data[27] != 0 ||
        data[26] < DISCOVERY_IPV6_FRAME_MIN - DISCOVERY_IPV6_HEADER_SIZE ||
        data[26] > DISCOVERY_FRAME_MAX - DISCOVERY_IPV6_HEADER_SIZE)
      return false;
    Ipv6Address ipv6;
    std::memcpy(ipv6.bytes.data(), data + 2, 16);
    address = DiscoveryAddress(ipv6);
    stride = data[26];
    header = DISCOVERY_IPV6_HEADER_SIZE;
    digest_offset = 18;
  } else
#endif
      if (data[15] == 0 && data[0] == 1 && data[14] == 0) {
    stride = DISCOVERY_CHUNK_SIZE;
  } else if (data[15] == 0 && data[0] == 2 && data[14] >= DISCOVERY_FRAME_MIN - DISCOVERY_HEADER_SIZE &&
             data[14] < DISCOVERY_CHUNK_SIZE) {
    stride = data[14];
  } else {
    return false;
  }
  if (header == DISCOVERY_HEADER_SIZE)
    std::memcpy(&address.ipv4, data + 2, 4);
  const uint32_t digest = read32(data + digest_offset);
  const size_t total = read16(data + digest_offset + 4), offset = read16(data + digest_offset + 6);
  if (!address.valid() || total == 0 || total > DISCOVERY_DESCRIPTOR_MAX || offset >= total || offset % stride != 0 ||
      length - header != (total - offset < stride ? total - offset : stride))
    return false;
  const size_t chunks = (total + stride - 1) / stride;
  if (chunks > 32)
    return false;
  auto &peer = this->peers_[node - 1];
  this->expire_assemblies_(now);
  if (this->assembly_(node) == nullptr)
    this->waiting_ |= uint16_t(1) << (node - 1);
  this->admit_waiters_(now);
  auto *owned = this->assembly_(node);
  if (owned == nullptr)
    return false;
  auto &assembly = *owned;
  if (!assembly.active || assembly.address != address || assembly.digest != digest || assembly.length != total ||
      assembly.stride != stride || uint32_t(now - assembly.started) >= 2000) {
    assembly.active = true;
    assembly.chunks = 0;
    assembly.address = address;
    assembly.digest = digest;
    assembly.length = total;
    assembly.stride = stride;
    // Full capacity retains the old independent per-peer restart semantics.
    // A reduced pool gives every admitted peer an absolute two-second grant.
    if constexpr (DISCOVERY_ASSEMBLY_SLOTS == mesh_limits::MAX_NODES)
      assembly.started = now;
  }
  const uint32_t bit = uint32_t(1) << (offset / stride);
  if ((assembly.chunks & bit) != 0)
    return std::memcmp(assembly.data.data() + offset, data + header, length - header) == 0;
  std::memcpy(assembly.data.data() + offset, data + header, length - header);
  assembly.chunks |= bit;
  const uint32_t all_chunks = chunks == 32 ? UINT32_MAX : (uint32_t(1) << chunks) - 1;
  if (assembly.chunks != all_chunks)
    return true;
  DescriptorView descriptor;
  if (discovery_digest(assembly.data.data(), total) != digest ||
      !parse_descriptor(assembly.data.data(), total, descriptor)) {
    this->clear_assembly_(node);
    return false;
  }
  const char hex[] = "0123456789abcdef";
  char mac[12];
  for (size_t i = 0; i < 6; ++i) {
    mac[2 * i] = hex[peer.mac[i] >> 4];
    mac[2 * i + 1] = hex[peer.mac[i] & 15];
  }
  for (size_t i = 0; i < descriptor.count; ++i)
    if (descriptor.items[i].key == "mac" && descriptor.items[i].value != std::string_view(mac, sizeof(mac))) {
      this->clear_assembly_(node);
      return false;
    }
  // A second allowed node may not overwrite another node's live hostname.
  for (size_t i = 0; i < mesh_limits::MAX_NODES; ++i) {
    const auto &other = this->peers_[i];
    if (i + 1 != node && other.descriptor_valid && uint32_t(now - other.seen) < DISCOVERY_LIFETIME_MS &&
        other.descriptor.hostname() == descriptor.hostname) {
      this->clear_assembly_(node);
      return false;
    }
  }
  if (!peer.descriptor_valid || peer.digest != digest || peer.address != address) {
    assign_descriptor(descriptor, peer.descriptor);
    peer.descriptor_valid = true;
    peer.digest = digest;
    peer.address = address;
    ++peer.revision;
  }
  peer.seen = now;
  this->clear_assembly_(node);
  return true;
}

const DiscoveryDescriptor *DiscoveryRegistry::current(uint8_t node, uint32_t address, uint32_t now) const {
  return this->current_(node, DiscoveryAddress(address), now);
}
#ifdef MESH_IPV6
const DiscoveryDescriptor *DiscoveryRegistry::current(uint8_t node, const Ipv6Address &address, uint32_t now) const {
  return this->current_(node, DiscoveryAddress(address), now);
}
bool DiscoveryRegistry::refresh(uint8_t node, const Ipv6Address &address, uint32_t now) {
  return this->refresh_(node, DiscoveryAddress(address), now);
}
#endif
const DiscoveryDescriptor *DiscoveryRegistry::current_(uint8_t node, const DiscoveryAddress &address,
                                                       uint32_t now) const {
  if (node == 0 || node > mesh_limits::MAX_NODES || !address.valid())
    return nullptr;
  const auto &peer = this->peers_[node - 1];
  return peer.descriptor_valid && peer.address == address && uint32_t(now - peer.seen) < DISCOVERY_LIFETIME_MS
             ? &peer.descriptor
             : nullptr;
}
uint32_t DiscoveryRegistry::revision(uint8_t node) const {
  return node >= 1 && node <= mesh_limits::MAX_NODES ? this->peers_[node - 1].revision : 0;
}
bool DiscoveryRegistry::refresh(uint8_t node, uint32_t address, uint32_t now) {
  return this->refresh_(node, DiscoveryAddress(address), now);
}
bool DiscoveryRegistry::refresh_(uint8_t node, const DiscoveryAddress &address, uint32_t now) {
  if (node == 0 || node > mesh_limits::MAX_NODES || !address.valid())
    return false;
  auto &peer = this->peers_[node - 1];
  if (!peer.descriptor_valid || peer.address != address || uint32_t(now - peer.seen) >= DISCOVERY_LIFETIME_MS)
    return false;
  peer.seen = now;
  return true;
}
void DiscoveryRegistry::forget(uint8_t node) {
  if (node == 0 || node > mesh_limits::MAX_NODES)
    return;
  auto &peer = this->peers_[node - 1];
  if (peer.descriptor_valid || this->assembly_(node) != nullptr) {
    peer.descriptor_valid = false;
    peer.descriptor.clear();
    ++peer.revision;
  }
  this->clear_assembly_(node);
}
void DiscoveryRegistry::expire(uint32_t now) {
  this->expire_assemblies_(now);
  this->admit_waiters_(now);
  for (auto &peer : this->peers_) {
    if (peer.descriptor_valid && uint32_t(now - peer.seen) >= DISCOVERY_LIFETIME_MS) {
      peer.descriptor_valid = false;
      peer.descriptor.clear();
    }
  }
}
}  // namespace mesh_ip
