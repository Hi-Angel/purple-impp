#include <string>
#include <utility>
#include "protocol.h"
#include <cassert>

using cstr = const std::string;
using nothing = std::monostate;

cstr to_hex(const uint8_t* arr, uint sz_arr) {
    const uint byte_image = 2, section = byte_image + 1;
    char buf[section * sz_arr];
    for (uint i = 0; i < sz_arr; ++i) {
        snprintf(buf + i * section, section, "%02X", arr[i]);
        buf[i * section + byte_image] = ' ';
    }
    return std::string(buf, buf+sizeof(buf)-1); // -1 for trailing space
}

cstr show_tlv_packet_header(const tlv_packet_header& h, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr chan = (h.channel == tlv_packet_header::version)? "version"
        : (h.channel == tlv_packet_header::tlv)? "tlv"
        : std::to_string(h.channel);
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    return "tlv_packet_header {"
        + newl_indent + "magic   = " + std::to_string(h.magic)
        + newl_indent + "channel = " + chan
        + "\n" + indent_base + "}";
}

cstr show_tlv_type(tlv_packet_data::tlv_family family, uint16_t type) {
    switch (family.get()) {
        case tlv_packet_data::FAMILY::stream:
            switch (type) {
                case STREAM::ERRORCODE: return "ERRORCODE";
                case STREAM::FEATURES:  return "FEATURES";
                case STREAM::MECHANISM: return "MECHANISM";
                case STREAM::NAME:      return "NAME";
                case STREAM::TIMESTAMP: return "TIMESTAMP";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::device:
            switch (type) {
                case DEVICE::ERRORCODE:           return "ERRORCODE";
                case DEVICE::CLIENT_NAME:         return "CLIENT_NAME";
                case DEVICE::CLIENT_PLATFORM:     return "CLIENT_PLATFORM";
                case DEVICE::CLIENT_MODEL:        return "CLIENT_MODEL";
                case DEVICE::CLIENT_ARCH:         return "CLIENT_ARCH";
                case DEVICE::CLIENT_VERSION:      return "CLIENT_VERSION";
                case DEVICE::CLIENT_BUILD:        return "CLIENT_BUILD";
                case DEVICE::CLIENT_DESCRIPTION:  return "CLIENT_DESCRIPTION";
                case DEVICE::DEVICE_NAME:         return "DEVICE_NAME";
                case DEVICE::IP_ADDRESS:          return "IP_ADDRESS";
                case DEVICE::CONNECTED_AT:        return "CONNECTED_AT";
                case DEVICE::STATUS:              return "STATUS";
                case DEVICE::STATUS_MESSAGE:      return "STATUS_MESSAGE";
                case DEVICE::CAPABILITIES:        return "CAPABILITIES";
                case DEVICE::IS_IDLE:             return "IS_IDLE";
                case DEVICE::IS_MOBILE:           return "IS_MOBILE";
                case DEVICE::IS_STATUS_AUTOMATIC: return "IS_STATUS_AUTOMATIC";
                case DEVICE::SERVER:              return "SERVER";
                case DEVICE::DEVICE_TUPLE:        return "DEVICE_TUPLE";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::lists:
            break; // todo
        case tlv_packet_data::FAMILY::im:
            break; // todo
        case tlv_packet_data::FAMILY::presence:
            break; // todo
        case tlv_packet_data::FAMILY::avatar:
            break; // todo
        case tlv_packet_data::FAMILY::group_chats:
            break; // todo
    }
    return std::to_string(type);
}

cstr show_tlv_unit(const std::vector<tlv_unit>& units, uint indent_offset, tlv_packet_data::tlv_family family) {
    if (units.size() == 0)
        return "";
    cstr indent_base = cstr(indent_offset, ' ');
    std::string ret;
    auto unit_to_str = [&indent_offset, &indent_base, &family](const tlv_unit& u) {
            cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
            cstr val_sz = "val_sz = " + ((u.is_val_sz32())? std::to_string(u.val_sz32.get())
                                        : std::to_string(u.val_sz16.get()));
            return "tlv_unit {"
                + newl_indent + "type   = " + show_tlv_type(family, u.type.get())
                + newl_indent + val_sz
                + newl_indent + "val[] = " + to_hex(u.val.data(), u.val.size())
                + "\n" + indent_base + "}\n";
        };
    ret += unit_to_str(units[0]);
    for (uint i = 1; i < units.size(); ++i)
        ret += indent_base + unit_to_str(units[i]);
    return ret;
}

cstr show_tlv_unit(const uint8_t* d, long int d_sz, uint indent_offset, tlv_packet_data::tlv_family family) {
    const std::vector<tlv_unit> units = deserialize_units(d, d_sz);
    return show_tlv_unit(units, indent_offset, family);
}

// human-readable view of the struct *not surrounded* by whitespace
cstr show_tlv_packet_data(const tlv_packet_data& packet, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    cstr flags = [packet]() -> cstr { // not yet clear if flags disjoint or not
            switch(packet.flags.get()) {
                case tlv_packet_data::request:    return cstr("request");
                case tlv_packet_data::response:   return cstr("response");
                case tlv_packet_data::indication: return cstr("indication");
                case tlv_packet_data::error:      return cstr("error");
                case tlv_packet_data::extension:  return cstr("extension");
                default: return "(unkn) " + std::to_string(packet.flags.get());
            }
        }();
    cstr family = [packet]() -> cstr {
            switch(packet.family.get()) {
                case tlv_packet_data::stream:      return cstr("stream");
                case tlv_packet_data::device:      return cstr("device");
                case tlv_packet_data::lists:       return cstr("lists");
                case tlv_packet_data::im:          return cstr("im");
                case tlv_packet_data::presence:    return cstr("presence");
                case tlv_packet_data::avatar:      return cstr("avatar");
                case tlv_packet_data::group_chats: return cstr("group_chats");
                default: return "(unkn) " + std::to_string(packet.family.get());
            }
        }();
    return "tlv_packet_data {"
        // don't align "head = ", it looks ugly in the output
        + newl_indent + "head = " + show_tlv_packet_header(packet.head, indent_offset+4)
        + newl_indent + "flags    = " + flags
        + newl_indent + "family   = " + family
        + newl_indent + "msg_type = " + std::to_string(packet.msg_type.get())
        + newl_indent + "sequence = " + std::to_string(packet.sequence.get())
        + newl_indent + "block_sz = " + std::to_string(packet.block_sz.get())
        + newl_indent + "block[]  = " + show_tlv_unit(packet.block, indent_offset+4, packet.family.get())
        + indent_base + "\n}";
}

cstr show_tlv_packet_version(const tlv_packet_version& v, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    return "tlv_packet_version {"
        + newl_indent + "head = " + show_tlv_packet_header(v.head, indent_offset+4)
        + newl_indent + "protocol_version = " + std::to_string(v.protocol_version.get())
        + indent_base + "\n}";
}

void print_tlv_packet_data(const tlv_packet_data& h) {
    puts(show_tlv_packet_data(h, 0).c_str());
}

void print_tlv_packet_version(const tlv_packet_version& v) {
    puts(show_tlv_packet_version(v, 0).c_str());
}

void print_tlv_packet_header(const tlv_packet_header& h) {
    puts(show_tlv_packet_header(h, 0).c_str());
}

const std::string show_tlv_packet(const uint8_t p[], uint p_sz) {
    const auto packet = deserialize_pckt(p, p_sz);
    if (std::holds_alternative<std::string>(packet))
        return std::get<std::string>(packet);
    else if (std::holds_alternative<tlv_packet_version>(packet))
        return show_tlv_packet_version(std::get<tlv_packet_version>(packet), 0);
    else if (std::holds_alternative<tlv_packet_data>(packet))
        return show_tlv_packet_data(std::get<tlv_packet_data>(packet), 0);
    else {
        assert(0);
        return "bug: unknown packet type!";
    }
}

void print_tlv_packet(const uint8_t p[], uint tlv_sz) {
    puts(show_tlv_packet(p, tlv_sz).c_str());
}
