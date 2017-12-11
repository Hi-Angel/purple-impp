#ifndef COMMON_CONSTS_H
#define COMMON_CONSTS_H

#include "protocol.h"

const uint8_t magic = 0x6f; // tlv_packet::magic should always be equal to it

// 14 is the version of at least 6.0.0 trillian client
const tlv_packet_version version_request = {magic, tlv_packet_header::version, uint16bg_t{14}};

#endif //COMMON_CONSTS_H
