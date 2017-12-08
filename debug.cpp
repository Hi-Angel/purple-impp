#include "protocol.h"
#include <variant>
#include <vector>
#include <iterator>

using namespace std;

int main(int argc, char *argv[])
{
    // const uint8_t request[] = {0x6f, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x80,
    //                            0xf7, 0x26, 0x86, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01,
    //                            0x00, 0x02, 0x00, 0x03};
    // const uint8_t request2[]= {0x6f, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
    //                            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01,
    //                            0x00, 0x02, 0x00, 0x03};
    // print_tlv_packet(request, sizeof(request));
    // print_tlv_packet(request2, sizeof(request2));
    // std::vector<uint8_t> vec = {1, 2};
    // tlv_unit u = {0, vec};
    // std::vector<uint8_t> uv = serialize(u);
    // fprintf(stderr, "uv sz is %lu\n", uv.size());

    // std::vector<tlv_unit> u2 = deserialize_units(uv.data(), uv.size());
    // fprintf(stderr, "u2 sz is %lu\n", u2.size());

    // auto u3 = deserialize<tlv_unit>(uv.data(), uv.size());
    // fprintf(stderr, "u3 sz is %lu\n", u3.size());
    const tlv_unit unit = { type: STREAM::FEATURES,
                            val: serialize(uint16bg_t{STREAM::FEATURE_TLS})};
    tlv_packet_data packet = { {magic: magic, channel: tlv_packet_header::tlv},
                                flags: tlv_packet_data::request, family: tlv_packet_data::stream,
                                msg_type: STREAM::FEATURES_SET, sequence: 0, block: {unit} };
    const std::vector<uint8_t> dat = serialize(packet);
    auto my_variant = deserialize_pckt(dat);
    if (holds_alternative<std::string>(my_variant))
        fputs(("err: " + std::get<std::string>(my_variant) + "\n").c_str(), stderr);
    print_tlv_packet_data(std::get<tlv_packet_data>(my_variant));
}
