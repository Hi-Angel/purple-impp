#ifndef COMMON_CONSTS_H
#define COMMON_CONSTS_H

#include "protocol.h"

const uint8_t magic = 0x6f; // tlv_packet::magic should always be equal to it
const char CLIENT_NAME[]        = "Purple";
const char CLIENT_PLATFORM[]    = "GNU/Linux"; //todo: needs to be detected
const char CLIENT_ARCH[]        = "x86_64"; //todo: detect
const char CLIENT_VERSION[]     = "0.1";
const char CLIENT_BUILD[]       = "0"; //todo: detect
const char DEVICE_NAME[]        = "libpurple";
const char CLIENT_DESCRIPTION[] = "Multiprotocol messenger based on libpurple";

// 14 is the version of at least 6.0.0 trillian client
const tlv_packet_version templ_version_request = {magic, tlv_packet_header::version, uint16bg_t{14}};

const tlv_packet_data templ_authorize = tlv_packet_data {
    head : tlv_packet_header {
        magic   : magic,
        channel : tlv_packet_header::tlv
    },
    flags    : tlv_packet_data::request,
    family   : tlv_packet_data::stream,
    msg_type : STREAM::AUTHENTICATE,
    sequence : 6,
    block  : {
        tlv_unit {
            type   : STREAM::MECHANISM,
            val : { 0x00, 0x01 }
        },
        tlv_unit {
            type   : STREAM::NAME,
            val : { 0x74, 0x72, 0x69, 0x63, 0x69, 0x61 }
        },
        tlv_unit {
            type   : STREAM::NAME,
            val : { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 }
        }}
};

const tlv_packet_data templ_client_info = tlv_packet_data {
    head : tlv_packet_header {
        magic   : magic,
        channel : tlv_packet_header::tlv
    },
    flags    : tlv_packet_data::request,
    family   : tlv_packet_data::device,
    msg_type : DEVICE::BIND,
    sequence : 7,
    block  : {
        tlv_unit {
            type   : DEVICE::CLIENT_NAME,
            val : { CLIENT_NAME, CLIENT_NAME + sizeof(CLIENT_NAME) - 1 }
        },
        tlv_unit {
            type   : DEVICE::CLIENT_PLATFORM,
            val : { CLIENT_PLATFORM, CLIENT_PLATFORM + sizeof(CLIENT_PLATFORM) - 1 }
        },
        tlv_unit {
            type   : DEVICE::CLIENT_ARCH,
            val : { CLIENT_ARCH, CLIENT_ARCH + sizeof(CLIENT_ARCH) - 1 }
        },
        tlv_unit {
            type   : DEVICE::CLIENT_VERSION,
            val : { CLIENT_VERSION, CLIENT_VERSION + sizeof(CLIENT_VERSION) - 1 }
        },
        tlv_unit {
            type   : DEVICE::CLIENT_BUILD,
            val : { CLIENT_BUILD, CLIENT_BUILD + sizeof(CLIENT_BUILD) - 1 }
        },
        tlv_unit {
            type   : DEVICE::DEVICE_NAME,
            val : { DEVICE_NAME, DEVICE_NAME + sizeof(DEVICE_NAME) - 1 }
        },
        tlv_unit {
            type   : DEVICE::STATUS,
            val : { 0x00, 0x01 } // todo: probably USER_STATUS_ONLINE from docs
        },
        tlv_unit {
            type   : DEVICE::IS_STATUS_AUTOMATIC,
            val : { 0x00 }
        },
        tlv_unit {
            type   : DEVICE::CAPABILITIES,
            val : { 0x00, 0x01, 0x42, 0x04, 0x00, 0x02, 0x42, 0x09, 0x42, 0x03, 0x42, 0x06, 0x42, 0x05, 0x42, 0x07, 0x42, 0x08 }
            // todo: I've no idea what capabilities this is, and docs not very helpful
        },
        tlv_unit {
            type   : DEVICE::CLIENT_DESCRIPTION,
            val : { CLIENT_DESCRIPTION, CLIENT_DESCRIPTION + sizeof(CLIENT_DESCRIPTION) - 1 }
        }}
};

#endif //COMMON_CONSTS_H
