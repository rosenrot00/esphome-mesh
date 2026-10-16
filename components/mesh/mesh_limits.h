#pragma once
#include <cstddef>
#include <cstdint>

// Whole-network compile-time endpoint capacity. Bit masks and replay serial
// windows deliberately retain their protocol width; this bounds ID tables.
#ifndef MESH_MAX_NODES
#define MESH_MAX_NODES 16
#endif
namespace mesh_limits {
constexpr uint8_t MAX_NODES = MESH_MAX_NODES;
static_assert(MAX_NODES == 4 || MAX_NODES == 8 || MAX_NODES == 16, "max_nodes supports 4, 8 or 16 endpoints");
constexpr size_t MAX_PEERS = MAX_NODES - 1;
constexpr uint16_t ID_MASK = static_cast<uint16_t>((1UL << MAX_NODES) - 1);
constexpr bool valid_node(uint8_t id) { return id >= 1 && id <= MAX_NODES; }
// Shared data-frame profile; no runtime/YAML mode or mixed-budget network.
#ifndef MESH_V2_FRAME_BUDGET
#define MESH_V2_FRAME_BUDGET 512
#endif
constexpr size_t NATIVE_FRAME_BUDGET = MESH_V2_FRAME_BUDGET;
static_assert(NATIVE_FRAME_BUDGET == 512 || NATIVE_FRAME_BUDGET == 1470,
              "Native ESP-NOW v2 frames support 512 or 1470 bytes");
constexpr uint16_t PROTOCOL_PAYLOAD_BUDGET = NATIVE_FRAME_BUDGET - 39;
#ifndef MESH_V2_RADIO_RX_CAPACITY
#if MESH_V2_FRAME_BUDGET == 512
#define MESH_V2_RADIO_RX_CAPACITY 16
#else
#define MESH_V2_RADIO_RX_CAPACITY 8
#endif
#endif
#ifndef MESH_V2_RADIO_TX_CAPACITY
#if MESH_MAX_NODES > 8
#define MESH_V2_RADIO_TX_CAPACITY 48
#else
#define MESH_V2_RADIO_TX_CAPACITY 24
#endif
#endif
constexpr size_t RADIO_RX_CAPACITY = MESH_V2_RADIO_RX_CAPACITY;
constexpr size_t RADIO_TX_CAPACITY = MESH_V2_RADIO_TX_CAPACITY;
static_assert(RADIO_RX_CAPACITY >= 8, "Native v2 retains at least eight receive slots");
static_assert(RADIO_TX_CAPACITY >= 3 * MAX_PEERS, "Every peer needs DATA, CONTROL and ADVERTISEMENT capacity");
}  // namespace mesh_limits
