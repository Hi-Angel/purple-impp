#include "protocol.h"

int main(int argc, char *argv[])
{
    const uint8_t request[] = {0x6f, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x80,
                               0xf7, 0x26, 0x86, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01,
                               0x00, 0x02, 0x00, 0x03};
    const uint8_t request2[]= {0x6f, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                               0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01,
                               0x00, 0x02, 0x00, 0x03};
    // print_tlv_packet(&request, sizeof(request));
    // print_tlv_packet(&request2, sizeof(request2));
    uint block_sz = sizeof(tlv_unit) + sizeof(tlv_unit16) + sizeof(STREAM::FEATURE_TLS);
    tlv_packet_data packet = { {magic: magic, channel: tlv_packet_header::tlv},
                                flags: tlv_packet_data::request, family: tlv_packet_data::stream,
                                msg_type: STREAM::FEATURES_SET, sequence: 0,
                                block_sz: block_sz };
    uint16bg_t type = { type: STREAM::FEATURES }, val_sz = sizeof(STREAM::FEATURE_TLS);
    uint16bg_t s = {STREAM::FEATURE_TLS};
    auto foo = tlv_nth_val(request, sizeof(request), 0);
    puts(show_tlv_unit(foo.first, foo.second, 0).c_str());
    tlv_nth_val(request, sizeof(request), 1);
    std::vector<uint8_t> dat = new_packet(&packet, type, val_sz, (uint8_t*)&s);
    // print_tlv_packet((uint8_t*)dat.data(), dat.size());
    return 0;
}
