/*
 * Trillian IMPP for libpurple/Pidgin
 * Copyright (c) 2017 Konstantin Kharlamov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "comm.h"
#include "protocol.h"
#include <cassert>
#include <string>
#include <utility>

using cstr = const std::string;
using nothing = std::monostate;

void hexdump(const unsigned char *buf, uint buflen) {
  for (uint i=0; i<buflen; i+=16) {
    fprintf(stderr, "%06x: ", i);
    for (uint j=0; j<16; j++)
      if (i+j < buflen)
        fprintf(stderr, "%02x ", buf[i+j]);
      else
        fprintf(stderr, "   ");
    fprintf(stderr, " ");
    for (uint j=0; j<16; j++)
      if (i+j < buflen)
          fprintf(stderr, "%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    fprintf(stderr, "\n");
  }
}

cstr to_hex(const uint8_t* arr, uint sz_arr) {
    if (sz_arr == 0)
        return "";
    const uint byte_image = 2, section = byte_image + 1;
    char buf[section * sz_arr];
    for (uint i = 0; i < sz_arr; ++i) {
        snprintf(buf + i * section, section, "%02X", arr[i]);
        buf[i * section + byte_image] = ' ';
    }

    // this is an ugly hack to get a hex+ascii. The correct way requires ½ a day of
    // twiddling snprintf()s with lots of offsets (the more so because snprintf() adds
    // zero bytes), I just don't consider the outcome worth that much effort.
    puts("impp: hex start");
    hexdump(arr, sz_arr);
    puts("impp: hex end");

    return {buf, buf+sizeof(buf)-1}; // -1 for trailing space
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
    cstr sz = (type & (1 << 15))? "(bits 32) " : "(bits 16) ";
    switch (family.get()) {
        case tlv_packet_data::FAMILY::stream:
            switch (type) {
                case STREAM::ERRORCODE: return sz + "ERRORCODE";
                case STREAM::FEATURES:  return sz + "FEATURES";
                case STREAM::MECHANISM: return sz + "MECHANISM";
                case STREAM::NAME:      return sz + "NAME";
                case STREAM::TIMESTAMP: return sz + "TIMESTAMP";
                case STREAM::PASSWORD:  return sz + "PASSWORD";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::device:
            switch (type) {
                case DEVICE::ERRORCODE:           return sz + "ERRORCODE";
                case DEVICE::CLIENT_NAME:         return sz + "CLIENT_NAME";
                case DEVICE::CLIENT_PLATFORM:     return sz + "CLIENT_PLATFORM";
                case DEVICE::CLIENT_MODEL:        return sz + "CLIENT_MODEL";
                case DEVICE::CLIENT_ARCH:         return sz + "CLIENT_ARCH";
                case DEVICE::CLIENT_VERSION:      return sz + "CLIENT_VERSION";
                case DEVICE::CLIENT_BUILD:        return sz + "CLIENT_BUILD";
                case DEVICE::CLIENT_DESCRIPTION:  return sz + "CLIENT_DESCRIPTION";
                case DEVICE::DEVICE_NAME:         return sz + "DEVICE_NAME";
                case DEVICE::IP_ADDRESS:          return sz + "IP_ADDRESS";
                case DEVICE::CONNECTED_AT:        return sz + "CONNECTED_AT";
                case DEVICE::STATUS:              return sz + "STATUS";
                case DEVICE::STATUS_MESSAGE:      return sz + "STATUS_MESSAGE";
                case DEVICE::CAPABILITIES:        return sz + "CAPABILITIES";
                case DEVICE::IS_IDLE:             return sz + "IS_IDLE";
                case DEVICE::IS_MOBILE:           return sz + "IS_MOBILE";
                case DEVICE::IS_STATUS_AUTOMATIC: return sz + "IS_STATUS_AUTOMATIC";
                case DEVICE::SERVER:              return sz + "SERVER";
                case DEVICE::DEVICE_TUPLE:        return sz + "DEVICE_TUPLE";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::lists:
            switch (type) {
                case LISTS::ERRORCODE:       return sz + "ERRORCODE";
                case LISTS::FROM:            return sz + "FROM";
                case LISTS::TO:              return sz + "TO";
                case LISTS::CONTACT_ADDRESS: return sz + "CONTACT_ADDRESS";
                case LISTS::PENDING_ADDRESS: return sz + "PENDING_ADDRESS";
                case LISTS::ALLOW_ADDRESS:   return sz + "ALLOW_ADDRESS";
                case LISTS::BLOCK_ADDRESS:   return sz + "BLOCK_ADDRESS";
                case LISTS::AVATAR_SHA1:     return sz + "AVATAR_SHA1";
                case LISTS::NICKNAME:        return sz + "NICKNAME";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::im:
            switch (type) {
                case IM::ERRORCODE:       return sz + "ERRORCODE";
                case IM::FROM:            return sz + "FROM";
                case IM::TO:              return sz + "TO";
                case IM::CAPABILITY:      return sz + "CAPABILITY";
                case IM::MESSAGE_ID:      return sz + "MESSAGE_ID";
                case IM::MESSAGE_SIZE:    return sz + "MESSAGE_SIZE";
                case IM::MESSAGE_CHUNK:   return sz + "MESSAGE_CHUNK";
                case IM::CREATED_AT:      return sz + "CREATED_AT";
                case IM::TIMESTAMP:       return sz + "TIMESTAMP";
                case IM::OFFLINE_MESSAGE: return sz + "OFFLINE_MESSAGE";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::presence:
            switch (type) {
                case PRESENCE::ERRORCODE:           return sz + "ERRORCODE";
                case PRESENCE::FROM:                return sz + "FROM";
                case PRESENCE::TO:                  return sz + "TO";
                case PRESENCE::STATUS:              return sz + "STATUS";
                case PRESENCE::STATUS_MESSAGE:      return sz + "STATUS_MESSAGE";
                case PRESENCE::IS_STATUS_AUTOMATIC: return sz + "IS_STATUS_AUTOMATIC";
                case PRESENCE::AVATAR_SHA1:         return sz + "AVATAR_SHA1";
                case PRESENCE::NICKNAME:            return sz + "NICKNAME";
                case PRESENCE::CAPABILITIES:        return sz + "CAPABILITIES";
                default: break;
            }
            break;
        case tlv_packet_data::FAMILY::avatar:
            break; // todo
        case tlv_packet_data::FAMILY::group_chats:
            switch (type) {
                case GROUP_CHATS::ERRORCODE:        return sz + "ERRORCODE";
                case GROUP_CHATS::FROM:             return sz + "FROM";
                case GROUP_CHATS::NAME:             return sz + "NAME";
                case GROUP_CHATS::MEMBER:           return sz + "MEMBER";
                case GROUP_CHATS::INITIAL:          return sz + "INITIAL";
                case GROUP_CHATS::MESSAGE:          return sz + "MESSAGE";
                case GROUP_CHATS::TIMESTAMP:        return sz + "TIMESTAMP";
                case GROUP_CHATS::GROUP_CHAT_TUPLE: return sz + "GROUP_CHAT_TUPLE";
                default: break;
            }
            break;
        default:
            return sz + std::to_string(type);
    }
    return sz + std::to_string(type);
}

cstr show_tlv_units(const std::vector<tlv_unit>& units,
                    uint indent_offset,
                    const tlv_packet_data& pckt ) {
    if (units.size() == 0)
        return "";
    cstr indent_base = cstr(indent_offset, ' ');
    std::string ret;
    auto unit_to_str = [&indent_offset, &indent_base, &pckt](const tlv_unit& u) {
            const tlv_packet_data::tlv_family& family = pckt.family;
            std::string val = (pckt.flags.get() == tlv_packet_data::error)? show_tlv_error(family, pckt.uint16_val_at(0))
                : to_hex(u.get_val().data(), u.get_val().size());
            cstr newl_indent = "\n" + indent_base + cstr(4, ' ');
            cstr val_sz = "val_sz = " + ((u.is_val_sz32())? std::to_string(u.val_sz32.get())
                                        : std::to_string(u.val_sz16.get()));
            return "tlv_unit {"
                + newl_indent + "type   = " + show_tlv_type(family, u.type.get())
                + newl_indent + val_sz
                + newl_indent + "val[] = " + val
                + "\n" + indent_base + "}\n";
        };
    ret += unit_to_str(units[0]);
    for (uint i = 1; i < units.size(); ++i)
        ret += indent_base + unit_to_str(units[i]);
    return ret;
}

cstr show_tlv_units(const uint8_t* d, long int d_sz, uint indent_offset, const tlv_packet_data& pckt) {
    const std::vector<tlv_unit> units = deserialize_units(d, d_sz);
    return show_tlv_units(units, indent_offset, pckt);
}

cstr show_tlv_error(tlv_packet_data::tlv_family family, uint16_t error) {
    auto err_unkn = [&error]()->cstr { return "(ERR UNKN) " + std::to_string(error); };
    if (is_global_err(error))
        switch (error) {
            case GLOBAL::SUCCESS:             return "SUCCESS";
            case GLOBAL::SERVICE_UNAVAILABLE: return "SERVICE_UNAVAILABLE";
            case GLOBAL::INVALID_CONNECTION:  return "INVALID_CONNECTION";
            case GLOBAL::INVALID_STATE:       return "INVALID_STATE";
            case GLOBAL::INVALID_TLV_FAMILY:  return "INVALID_TLV_FAMILY";
            case GLOBAL::INVALID_TLV_LENGTH:  return "INVALID_TLV_LENGTH";
            case GLOBAL::INVALID_TLV_VALUE:   return "INVALID_TLV_VALUE";
            default: return err_unkn();
        }
    switch(family.get()) {
        case tlv_packet_data::stream: switch (error){
            case STREAM::FEATURE_INVALID:        return "FEATURE_INVALID";
            case STREAM::MECHANISM_INVALID:      return "MECHANISM_INVALID";
            case STREAM::AUTHENTICATION_INVALID: return "AUTHENTICATION_INVALID";
            default: return err_unkn();
        }
        case tlv_packet_data::device:switch (error) {
            case DEVICE::CLIENT_INVALID:         return "CLIENT_INVALID";
            case DEVICE::DEVICE_COLLISION:       return "DEVICE_COLLISION";
            case DEVICE::TOO_MANY_DEVICES:       return "TOO_MANY_DEVICES";
            case DEVICE::DEVICE_BOUND_ELSEWHERE: return "DEVICE_BOUND_ELSEWHERE";
            default: return err_unkn();
        }
        case tlv_packet_data::lists: switch (error) {
            case LISTS::LIST_LIMIT_EXCEEDED:    return "LIST_LIMIT_EXCEEDED";
            case LISTS::ADDRESS_EXISTS:         return "ADDRESS_EXISTS";
            case LISTS::ADDRESS_DOES_NOT_EXIST: return "ADDRESS_DOES_NOT_EXIST";
            case LISTS::ADDRESS_CONFLICT:       return "ADDRESS_CONFLICT";
            case LISTS::ADDRESS_INVALID:        return "ADDRESS_INVALID";
            default: return err_unkn();
        }
        case tlv_packet_data::im: switch (error) {
            case IM::USERNAME_BLOCKED:     return "USERNAME_BLOCKED";
            case IM::USERNAME_NOT_CONTACT: return "USERNAME_NOT_CONTACT";
            case IM::INVALID_CAPABILITY:   return "INVALID_CAPABILITY";
            default: return err_unkn();
        }
        case tlv_packet_data::presence:
            return err_unkn(); // no known errors
        case tlv_packet_data::group_chats: switch (error) {
            case GROUP_CHATS::MEMBER_NOT_CONTACT:    return "MEMBER_NOT_CONTACT";
            case GROUP_CHATS::MEMBER_ALREADY_EXISTS: return "MEMBER_ALREADY_EXISTS";
            default: return err_unkn();
        }
        case tlv_packet_data::avatar: // fall through
        default: return std::to_string(error);
    }
}

cstr show_msg_type(tlv_packet_data::tlv_family family, uint16_t msg_type) {
    switch(family.get()) {
        case tlv_packet_data::stream: switch (msg_type){
            case STREAM::FEATURES_SET:        return "FEATURES_SET";
            case STREAM::AUTHENTICATE:        return "AUTHENTICATE";
            case STREAM::PING:                return "PING";
            default: return std::to_string(msg_type);
        }
        case tlv_packet_data::device: switch (msg_type) {
            case DEVICE::BIND:                return "BIND";
            case DEVICE::UPDATE:              return "UPDATE";
            case DEVICE::UNBIND:              return "UNBIND";
            default: return std::to_string(msg_type);
        }
        case tlv_packet_data::lists: switch (msg_type) {
            case LISTS::GET:                  return "GET";
            case LISTS::CONTACT_ADD:          return "CONTACT_ADD";
            case LISTS::CONTACT_REMOVE:       return "CONTACT_REMOVE";
            case LISTS::CONTACT_AUTH_REQUEST: return "CONTACT_AUTH_REQUEST";
            case LISTS::CONTACT_APPROVE:      return "CONTACT_APPROVE";
            case LISTS::CONTACT_APPROVED:     return "CONTACT_APPROVED";
            case LISTS::CONTACT_DENY:         return "CONTACT_DENY";
            case LISTS::ALLOW_ADD:            return "ALLOW_ADD";
            case LISTS::ALLOW_REMOVE:         return "ALLOW_REMOVE";
            case LISTS::BLOCK_ADD:            return "BLOCK_ADD";
            case LISTS::BLOCK_REMOVE:         return "BLOCK_REMOVE";
            default: return std::to_string(msg_type);
        }
        case tlv_packet_data::im: switch (msg_type) {
            case IM::OFFLINE_MESSAGES_GET:    return "OFFLINE_MESSAGES_GET";
            case IM::OFFLINE_MESSAGES_DELETE: return "OFFLINE_MESSAGES_DELETE";
            case IM::MESSAGE_SEND:            return "MESSAGE_SEND";
            default: return std::to_string(msg_type);
        }
        case tlv_packet_data::presence: switch (msg_type) {
            case PRESENCE::SET:    return "SET";
            case PRESENCE::GET:    return "GET";
            case PRESENCE::UPDATE: return "UPDATE";
            default: return std::to_string(msg_type);
        }
        case tlv_packet_data::avatar: // fall through
        case tlv_packet_data::group_chats: switch (msg_type) { // fall through
            case GROUP_CHATS::SET:            return "SET";
            case GROUP_CHATS::GET:            return "GET";
            case GROUP_CHATS::MEMBER_ADD:     return "MEMBER_ADD";
            case GROUP_CHATS::MEMBER_REMOVE:  return "MEMBER_REMOVE";
            case GROUP_CHATS::MESSAGE_SEND:   return "MESSAGE_SEND";
            default: return std::to_string(msg_type);
        }
        default: return std::to_string(msg_type);
    }
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
        + newl_indent + "msg_type = " + show_msg_type(packet.family, packet.msg_type.get())
        + newl_indent + "sequence = " + std::to_string(packet.sequence.get())
        + newl_indent + "block_sz = " + std::to_string(packet.block_sz.get())
        + newl_indent + "block[]  = " + show_tlv_units(packet.get_block(), indent_offset+4, packet)
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
