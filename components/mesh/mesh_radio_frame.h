#pragma once

#include "mesh_limits.h"

#include "mesh_core.h"

namespace mesh_radio {

// RX metadata describes the receiver's tuning, so an adjacent-channel packet
// cannot prove the sender uses that same channel. Carry the sender's actual PHY
// inside the encrypted unicast, while keeping the portable core wire unchanged.
constexpr size_t ADVERTISEMENT_RADIO_TRAILER_SIZE = 4;

inline bool encode_radio_frame(const ::mesh_core::Frame &frame, uint8_t channel, uint8_t *output, size_t capacity,
                               size_t &written) {
  written = 0;
  const bool advertisement = frame.type == ::mesh_core::FrameType::ADVERTISEMENT;
  if (advertisement && (channel < 1 || channel > 14 ||
                        capacity < ::mesh_core::wire_header_size(frame) + ADVERTISEMENT_RADIO_TRAILER_SIZE))
    return false;
  if (!::mesh_core::encode_frame(frame, output, capacity, written))
    return false;
  if (advertisement) {
    output[written++] = 'R';
    output[written++] = 'C';
    output[written++] = 1;
    output[written++] = channel;
  }
  return true;
}

inline bool decode_radio_frame(const uint8_t *input, size_t length, uint8_t local_channel, ::mesh_core::Frame &frame) {
  if (input == nullptr || length < ::mesh_core::kWireHeaderSize)
    return false;
  if (input[3] == static_cast<uint8_t>(::mesh_core::FrameType::ADVERTISEMENT)) {
    const size_t offset = ::mesh_core::wire_header_size_for_version(input[2]);
    if (offset == 0 || length != offset + ADVERTISEMENT_RADIO_TRAILER_SIZE || local_channel < 1 || local_channel > 14 ||
        input[offset] != 'R' || input[offset + 1] != 'C' || input[offset + 2] != 1 ||
        input[offset + 3] != local_channel)
      return false;
    length = offset;  // The core still validates a zero-payload advertisement.
  }
  return ::mesh_core::decode_frame(input, length, frame);
}

}  // namespace mesh_radio
