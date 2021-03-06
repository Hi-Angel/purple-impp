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

#ifndef PROTOCOL_H
#define PROTOCOL_H

/* This file contains common IMPP structures and types */

#include <cassert>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

//source: https://stackoverflow.com/a/4956493/2388257
// todo: use htons()'n'co in case somebody uses a big-endian CPU
template <typename T>
T swap_endian(T u) {
    union {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

template<typename T>
struct big_endian {
    big_endian() : val(T()) {};
    big_endian(T t) : val(swap_endian(t)) {}

    big_endian(const big_endian<T>& a) : val(a.val) {}
    T get() const { return swap_endian(val); }

    // used by Cereal for (de)serialization
    template<class Archive>
    void serialize(Archive& archive) {
        archive(val);
    }

    big_endian<T>& operator=(const big_endian<T>&) = default;
private: // to not occasionally mess with endianess
    T val;
};

using uint32bg_t = big_endian<uint32_t>;
using uint16bg_t = big_endian<uint16_t>;
using uint = unsigned int;

namespace GLOBAL {
enum ERROR: uint16_t {
    SUCCESS             = 0,
    SERVICE_UNAVAILABLE = 1,
    INVALID_CONNECTION  = 2,
    INVALID_STATE       = 3,
    INVALID_TLV_FAMILY  = 4,
    INVALID_TLV_LENGTH  = 5,
    INVALID_TLV_VALUE   = 6
};
}

namespace STREAM {
/* a tlv_packet msg */
enum MSG_TYPE: uint16_t {
    FEATURES_SET = 1,
    AUTHENTICATE = 2,
    PING         = 3
};

/* a tlv_unit type */
enum TLV_TYPE: uint16_t {
    ERRORCODE = 0,
    FEATURES  = 1,
    MECHANISM = 2, // 16 bit, I know only of val = MECHANISM_PASSWORD = 1
    NAME      = 3, // 16 bit
    TIMESTAMP = 4, // 16 bit
    PASSWORD  = 5  // 16 bit
};

/* a tlv_unit::val, can be used with bitmask */
enum TLV_VAL: uint16_t {
    FEATURE_NONE        = 0,
    FEATURE_TLS         = 1,
    FEATURE_COMPRESSION = 2
};
enum ERROR: uint16_t {
    FEATURE_INVALID        = 0x8001,
    MECHANISM_INVALID      = 0x8002,
    AUTHENTICATION_INVALID = 0x8003
};
}

namespace DEVICE {
/* a tlv_packet msg_type */
enum MSG_TYPE: uint16_t {
    BIND   = 1,
    UPDATE = 2,
    UNBIND = 3
};

enum TLV_TYPE: uint16_t {
    ERRORCODE           = 0,
    CLIENT_NAME         = 1,
    CLIENT_PLATFORM     = 2,
    CLIENT_MODEL        = 3,
    CLIENT_ARCH         = 4,
    CLIENT_VERSION      = 5,
    CLIENT_BUILD        = 6,
    CLIENT_DESCRIPTION  = 7,
    DEVICE_NAME         = 8,
    IP_ADDRESS          = 9,
    CONNECTED_AT        = 10,
    STATUS              = 11,
    STATUS_MESSAGE      = 12,
    CAPABILITIES        = 13,
    IS_IDLE             = 14,
    IS_MOBILE           = 15,
    IS_STATUS_AUTOMATIC = 16,
    SERVER              = 17,
    DEVICE_TUPLE        = 18
};
enum ERROR: uint16_t {
    CLIENT_INVALID         = 0x8001,
    DEVICE_COLLISION       = 0x8002,
    TOO_MANY_DEVICES       = 0x8003,
    DEVICE_BOUND_ELSEWHERE = 0x8004
};
}

namespace LISTS {
/* a tlv_packet msg_type */
enum MSG_TYPE: uint16_t {
    GET                  = 0x1,
    CONTACT_ADD          = 0x2,
    CONTACT_REMOVE       = 0x3,
    CONTACT_AUTH_REQUEST = 0x4,
    CONTACT_APPROVE      = 0x5,
    CONTACT_APPROVED     = 0x6,
    CONTACT_DENY         = 0x7,
    ALLOW_ADD            = 0x8,
    ALLOW_REMOVE         = 0x9,
    BLOCK_ADD            = 0xa,
    BLOCK_REMOVE         = 0xb
};

enum TLV_TYPE: uint16_t {
    ERRORCODE       = 0,
    FROM            = 1, // 16 bits
    TO              = 2, // 16 bits
    CONTACT_ADDRESS = 3,
    PENDING_ADDRESS = 4,
    ALLOW_ADDRESS   = 5,
    BLOCK_ADDRESS   = 6,
    AVATAR_SHA1     = 7,
    NICKNAME        = 8
};
enum ERROR: uint16_t {
    LIST_LIMIT_EXCEEDED    = 0x8001,
    ADDRESS_EXISTS         = 0x8002,
    ADDRESS_DOES_NOT_EXIST = 0x8003,
    ADDRESS_CONFLICT       = 0x8004,
    ADDRESS_INVALID        = 0x8005
};
}

namespace GROUP_CHATS {
/* a tlv_packet msg_type */
enum MSG_TYPE: uint16_t {
    SET           = 1,
    GET           = 2,
    MEMBER_ADD    = 3,
    MEMBER_REMOVE = 4,
    MESSAGE_SEND  = 5
};

enum TLV_TYPE: uint16_t {
    ERRORCODE        = 0,
    FROM             = 1,
    NAME             = 2,
    MEMBER           = 3,
    INITIAL          = 4,
    MESSAGE          = 5,
    TIMESTAMP        = 6,
    GROUP_CHAT_TUPLE = 7
};
enum ERROR: uint16_t {
    MEMBER_NOT_CONTACT    = 0x8001,
    MEMBER_ALREADY_EXISTS = 0x8002
};
}

namespace IM {
const uint16_t CAPABILITY_IM     = 1;
const uint16_t CAPABILITY_TYPING = 2;
const uint16_t TYPING_STOPPED    = 0; // undocumented
const uint16_t TYPING_STARTED    = 2; // undocumented

/* a tlv_packet msg_type */
enum MSG_TYPE: uint16_t {
    OFFLINE_MESSAGES_GET    = 1,
    OFFLINE_MESSAGES_DELETE = 2,
    MESSAGE_SEND            = 3
};

enum TLV_TYPE: uint16_t {
    ERRORCODE       = 0,
    FROM            = 1, // 16 bits
    TO              = 2, // 16 bits
    CAPABILITY      = 3, // 16 bits
    MESSAGE_ID      = 4,
    MESSAGE_SIZE    = 5,
    MESSAGE_CHUNK   = 6, // 16 bits
    CREATED_AT      = 7, // 16 bits
    TIMESTAMP       = 8, // 16 bits
    OFFLINE_MESSAGE = 9, // 16 bits

    // undocumented, used at least in tlv_unit::type of OFFLINE_MESSAGES_GET, whereas
    // the value field are tlv_units of the form `templ_user_msg_body`.
    MSG_BATCH       = 10
};
enum ERROR: uint16_t {
    USERNAME_BLOCKED     = 0x8001,
    USERNAME_NOT_CONTACT = 0x8002,
    INVALID_CAPABILITY   = 0x8003
};
}

namespace PRESENCE {
/* a tlv_packet msg_type */
enum MSG_TYPE: uint16_t {
    SET    = 1,
    GET    = 2,
    UPDATE = 3
};

enum TLV_TYPE: uint16_t {
    ERRORCODE           = 0,
    FROM                = 1,
    TO                  = 2,
    STATUS              = 3,
    STATUS_MESSAGE      = 4,
    IS_STATUS_AUTOMATIC = 5,
    AVATAR_SHA1         = 6,
    NICKNAME            = 7,
    CAPABILITIES        = 8
};
}

struct tlv_unit {
    uint16bg_t type; // meaning of a type depends to their family
    union {
        // whether 32 or 16 determines most significant bit of the type. 1 ⇒ 32, 0 ⇒
        // 16. Also, quoting docs "Because the most significant bit of a TLV type is
        // reserved, the allowable range of values for TLV types is 0-32767". This
        // means MSB is checked in big-endian.
        uint16bg_t val_sz16;
        uint32bg_t val_sz32;
    };
private: // changing val requires changes to val_sz* as well, use (g)set_val()
    std::vector<uint8_t>  val;
public:

    const std::vector<uint8_t>& get_val() const { return val; }
    void set_val(const std::vector<uint8_t> v) {
        val = v;
        if (is_val_sz32())
            val_sz32 = val.size();
        else
            val_sz16 = val.size();
    }

    // used by Cereal for (de)serialization
    template<class Archive>
    void save(Archive& archive) const {
        archive(type);
        if (is_val_sz32())
            archive(val_sz32);
        else
            archive(val_sz16);
        for(auto b : val)
            archive(b);
    }
    template<class Archive>
    void load(Archive& archive) {
        archive(type);
        if (is_val_sz32())
            archive(val_sz32);
        else
            archive(val_sz16);
        unsigned val_sz = (is_val_sz32())? val_sz32.get() : val_sz16.get();
        val.reserve(val_sz);
        val.clear(); // make sure it's empty in case the object is second-hand
        uint8_t tmp;
        for(unsigned i = 0; i < val_sz; ++i) {
            archive(tmp);
            val.push_back(tmp);
        }
    }

    tlv_unit(){}
    tlv_unit(const tlv_unit& u): type(u.type), val(u.val) {
        if (is_val_sz32())
            val_sz32 = u.val_sz32;
        else
            val_sz16 = u.val_sz16;
    }
    tlv_unit(uint16_t t, const std::vector<uint8_t>& vec): type(t), val(vec) {
        if (is_val_sz32())
            val_sz32 = vec.size();
        else
            val_sz16 = vec.size();
    }

    bool is_val_sz32 () const { return type.get() & (1 << 15);}

    // Deserialized size
    uint size() const {
        return sizeof(type) + ((is_val_sz32())? sizeof(val_sz32) + val_sz32.get()
                               : sizeof(val_sz16) + val_sz16.get());
    }
};

struct tlv_packet_header {
    uint8_t magic; // should always be 0x6f
    enum : uint8_t {
        version = 0x1,
        tlv     = 0x2
    } channel;

    // used by Cereal for (de)serialization
    template<class Archive>
    void serialize(Archive& archive) {
        archive(magic, channel);
    }
};

struct tlv_packet_version {
    tlv_packet_header head;
    uint16bg_t protocol_version;

    // used by Cereal for (de)serialization
    template<class Archive>
    void serialize(Archive& archive) {
        archive(head, protocol_version);
    }
};

struct tlv_packet_data {
    /* just type declarations, they do not contribute a size unless being used */
    enum TLV_FLAGS : uint16_t {
        request    = 0,
        response   = 1,
        indication = 2,
        error      = 4,
        extension  = 8
    };
    using tlv_flags = big_endian<TLV_FLAGS>;

    enum FAMILY : uint16_t {
        stream      = 1,
        device      = 2,
        lists       = 3,
        im          = 4,
        presence    = 5,
        avatar      = 6,
        group_chats = 7
    };
    using tlv_family = big_endian<FAMILY>;

    /*********************/
    tlv_packet_header head;

    /* 1. A request. If the response, indication, and error bits are all set to 0, the
       message is a request. Requests are the only type of messages sent by clients to
       servers.

       2. A response. Responses are sent from server to client and are always tied to
       a particular request. The sequence number of a response will correspond to the
       request the response belongs to.

       3. An indication. Indications are "server-initiated" messages not tied to any
       particular client request. The sequence number of an indication will always be
       set to 0.

       4. An error. Errors are typically tied to a particular request but MAY be
       stateless. The sequence number will either be 0 or the sequence number of the
       request that resulted in an error.*/
    tlv_flags flags;

    /* The most significant bit of a message family value is reserved. The allowable
       range of values for families is therefore 0-32767. Within that range:

       1. The values from 0-16383 are reserved for the core IMPP protocol.

       2. The values from 16384-32767 are reserved for extensions and are not defined
       as a part of the core IMPP protocol. Clients and servers MUST mark all messages
       from extended families with the extension bit. */
    tlv_family family;

    /* Meaning determiend by family.

       The most significant bit of a message type value is reserved. The allowable
       range of values for types is therefore 0-32767. Within that range:

       1. The values from 0-16383 are reserved for the core IMPP protocol.

       2. The values from 16384-32767 are reserved for extensions and are not defined
       as a part of the core IMPP protocol. Clients and servers MUST mark all messages
       from extended types with the extension bit. */
    uint16bg_t msg_type;

    /* TLV messages are sequenced and MUST be sent in sequenced order. Messages
       received by the server are processed in per-family FIFO order. The sequence
       value itself starts at a random value and is incremented by one for every
       message regardless of family. For example, a client may send three messages:

       1. LISTS::CONTACT_ADD with sequence 100.
       2. LISTS::CONTACT_REMOVE with sequence 101.
       3. PRESENCE::SET with sequence 102.

       In this example, the server will process the first request, hold the second
       request until it's finished with the first, and process the third request
       immediately. Once the server responds to request 100, (which may involve
       backend communication with a database, thereby requiring a wait period) it is
       then allowed to continue processing messages within the LISTS family. Responses
       from the server can therefore come out-of-order. Clients MUST store the
       sequence associated with a message and be prepard to act on its response at any
       time.*/
    uint32bg_t sequence;
    uint32bg_t block_sz; // block size in bytes
private: // block should not be changed directly because of block_sz
    std::vector<tlv_unit> block;
public:

    // used by Cereal for (de)serialization
    template<class Archive>
    void save(Archive& archive) const {
        archive(head, flags, family, msg_type, sequence, block_sz);
        for(auto u : block)
            archive(u);
    }
    template<class Archive>
    void load(Archive& archive) {
        archive(head, flags, family, msg_type, sequence, block_sz);
        tlv_unit u;
        for (long int sz = block_sz.get(); sz > 0;) {
            try {archive(u);} catch(...) {
                fputs("wrn: a tlv_unit wasn't deserialized\n", stderr);
                break;
            }
            block.push_back(u);
            sz -= u.size();
            assert(sz >= 0); // otherwise we took excess bytes
        }
    }

    // constructor without block_sz argument
    tlv_packet_data() {}
    tlv_packet_data(tlv_packet_header h, tlv_flags flgs, tlv_family fam,
                    uint16bg_t msg_t, uint32bg_t seq, std::vector<tlv_unit> blck):
        head(h), flags(flgs), family(fam), msg_type(msg_t),
        sequence(seq), block(blck) {
        uint sz = 0;
        for (uint i = 0; i < block.size(); ++i)
            sz += block[i].size();
        block_sz = {sz};
    }

    static const uint min_data_pckt_sz = sizeof(tlv_packet_header) + sizeof(flags)
        + sizeof(family) + sizeof(msg_type) + sizeof(sequence) + sizeof(block_sz);

    uint curr_pckt_sz() const { return min_data_pckt_sz + block_sz.get(); }

    // *unsafe* helpers, ensure whatever you're accessing exists before calling
    uint16_t uint16_val_at(uint unit_i) const {
        return ((uint16bg_t*)block[unit_i].get_val().data())->get();
    }
    uint szval_at(uint unit_i) const {
        const tlv_unit& u = block[unit_i];
        return (u.is_val_sz32())? u.val_sz32.get() : u.val_sz16.get();
    }

    void set_tlv_val(const uint i, const std::vector<uint8_t> new_val) {
        block_sz = block_sz.get() + new_val.size() - block[i].get_val().size();
        block[i].set_val(new_val);
    }
    const std::vector<tlv_unit>& get_block() const { return block; }
};

void print_tlv_packet_data(const tlv_packet_data& h);
void print_tlv_packet_version(const tlv_packet_version& v);
void print_tlv_packet(const uint8_t p[], uint tlv_sz);
const std::string show_tlv_packet(const uint8_t p[], uint tlv_sz);
const std::string show_tlv_packet_data(const tlv_packet_data& packet, uint indent_offset);
const std::string show_tlv_units(const uint8_t d[], long int d_sz,
                                 uint indent_offset, const tlv_packet_data& pckt);
const std::string show_tlv_error(tlv_packet_data::tlv_family family, uint16_t error);
const std::string to_hex(uint8_t* arr, uint sz_arr);

// templates can't be exported, so we have to restort to ugly hacks
std::vector<uint8_t> serialize(const tlv_unit&);
std::vector<uint8_t> serialize(const tlv_packet_data&);
std::vector<uint8_t> serialize(const tlv_packet_version&);
std::vector<uint8_t> serialize(const uint32bg_t&);
std::vector<uint8_t> serialize(const uint16bg_t&);

std::variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const uint8_t dat[], uint sz_dat);
std::variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const std::vector<uint8_t>& dat);
std::vector<tlv_unit> deserialize_units(const uint8_t dat[], uint sz_dat);

#endif //PROTOCOL_H
