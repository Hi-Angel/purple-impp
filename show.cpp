#include <string>
#include <utility>
#include "protocol.h"

using cstr = const std::string;

std::string to_hex(uint8_t* arr, uint sz_arr) {
    const uint byte_image = 2, section = byte_image + 1;
    char buf[section * sz_arr];
    for (uint i = 0; i < sz_arr; ++i) {
        snprintf(buf + i * section, section, "%02X", arr[i]);
        buf[i * section + byte_image] = ' ';
    }
    return std::string(buf, buf+sizeof(buf)-1); // -1 for trailing space
}

#define SHOW_TLV_UNIT_N(bits)                                           \
    {                                                                   \
        if (d_sz < (int)sizeof(tlv_unit##bits)) {                       \
            units += "<not enough size for val_sz>";                    \
            break;                                                      \
        }                                                               \
        tlv_unit##bits* un = (tlv_unit##bits*)u;                        \
        units += std::to_string(un->val_sz.get()) + newl_indent;        \
        if (d_sz - sizeof(un->val_sz) <= 0) {                            \
            units += "val[] = <not enough size for val>";               \
            break;                                                      \
        }                                                               \
        uint real_val_sz = ((int)(un->val_sz.get() + sizeof(un->val_sz)) <= d_sz)? un->val_sz.get() \
            : d_sz - sizeof(un->val_sz);                                \
        units += "val[] = " + to_hex(un->val, real_val_sz);             \
        d_sz -= sizeof(*un) + real_val_sz;                              \
        u = inc_by_bytes(u, sizeof(*un) + real_val_sz);                 \
    }

cstr show_tlv_unit(const uint8_t* d, long int d_sz, uint indent_offset) {
    cstr indent_base = cstr(indent_offset, ' ');
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    std::string units;
    for (const tlv_unit* u = (tlv_unit*)d; d_sz >= (int)sizeof(tlv_unit);) {
        units += "tlv_unit {"
            + newl_indent + "type   = "+ std::to_string(u->type.get())
            + newl_indent + "val_sz = ";
        d_sz -= sizeof(tlv_unit);
        u = inc_by_bytes(u, sizeof(tlv_unit)); // todo wtf??
        if (u->type.get() & (1 << 15))
            SHOW_TLV_UNIT_N(32)
        else
            SHOW_TLV_UNIT_N(16)
        units += "\n" + indent_base + "}\n";
    }
    return units;
}

// human-readable view of the struct *not surrounded* by whitespace
cstr show_tlv_packet_header(const tlv_packet_header* h, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr chan = (h->channel == tlv_packet_header::version)? "version"
        : (h->channel == tlv_packet_header::tlv)? "tlv"
        : std::to_string(h->channel);
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    return "tlv_packet_header {"
        + newl_indent + "magic   = " + std::to_string(h->magic)
        + newl_indent + "channel = " + chan
        + "\n" + indent_base + "}";
}

// human-readable view of the struct *not surrounded* by whitespace
cstr show_tlv_packet_data(const tlv_packet_data* h, uint tlv_sz, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    const std::pair<cstr,uint> block_sz = [h,tlv_sz]() -> std::pair<cstr,uint> {
            if (h->block_sz.get() <= tlv_sz - sizeof(tlv_packet_data))
                return {"block_sz = " + std::to_string(h->block_sz.get()),
                        h->block_sz.get()};
            else
                return {"block_sz = " + cstr("(wrn: too big, capping!) ")
                        + std::to_string(tlv_sz - sizeof(tlv_packet_data)),
                        tlv_sz - sizeof(tlv_packet_data)};
        }();
    cstr flags = [h]() -> cstr { // not yet clear if flags disjoint or not
            switch(h->flags.get()) {
                case tlv_packet_data::request: return cstr("request");
                case tlv_packet_data::response: return cstr("response");
                case tlv_packet_data::indication: return cstr("indication");
                case tlv_packet_data::error: return cstr("error");
                case tlv_packet_data::extension: return cstr("extension");
                default: return "(unkn) " + std::to_string(h->flags.get());
            }
        }();
    cstr family = [h]() -> cstr { // not yet clear if flags disjoint or not
            switch(h->family.get()) {
                case tlv_packet_data::stream: return cstr("stream");
                case tlv_packet_data::device: return cstr("device");
                case tlv_packet_data::lists: return cstr("lists");
                case tlv_packet_data::im: return cstr("im");
                case tlv_packet_data::presence: return cstr("presence");
                case tlv_packet_data::avatar: return cstr("avatar");
                case tlv_packet_data::group_chats: return cstr("group_chats");
                default: return "(unkn) " + std::to_string(h->family.get());
            }
        }();
    return "tlv_value_header {"
        // don't align "head =", it looks ugly in the output
        + newl_indent + "head = " + show_tlv_packet_header(&h->head, indent_offset+4)
        + newl_indent + "flags    = " + flags
        + newl_indent + "family   = " + family
        + newl_indent + "msg_type = " + std::to_string(h->msg_type.get())
        + newl_indent + "sequence = " + std::to_string(h->sequence.get())
        + newl_indent + block_sz.first
        + newl_indent + "block[] = " + show_tlv_unit(h->block, block_sz.second, indent_offset+4)
        + indent_base + "\n}";
}

cstr show_tlv_packet_version(const tlv_packet_version* v, uint indent_offset){
    cstr indent_base = cstr(indent_offset, ' ');
    cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
    return "tlv_packet_version {"
        + newl_indent + "head = " + show_tlv_packet_header(&v->head, indent_offset+4)
        + newl_indent + "protocol_version = " + std::to_string(v->protocol_version.get())
        + indent_base + "\n}";
}

void print_tlv_packet_data(const tlv_packet_data* h, uint tlv_sz) {
    puts(show_tlv_packet_data(h, tlv_sz, 0).c_str());
}

void print_tlv_packet_version(const tlv_packet_version* v) {
    puts(show_tlv_packet_version(v, 0).c_str());
}

void print_tlv_packet_header(const tlv_packet_header* h) {
    puts(show_tlv_packet_header(h, 0).c_str());
}

std::string show_tlv_packet(const void* p, uint tlv_sz) {
    const tlv_packet_header* packet = (tlv_packet_header*)p;
    if (packet->channel == tlv_packet_header::tlv)
        return show_tlv_packet_data((tlv_packet_data*)p, tlv_sz, 0);
    else if (packet->channel == tlv_packet_header::version)
        return show_tlv_packet_header((tlv_packet_header*)p, 0);
    else
        return "unknown packet channel, not printing";
}

void print_tlv_packet(const void* p, uint tlv_sz) {
    puts(show_tlv_packet(p, tlv_sz).c_str());
}
