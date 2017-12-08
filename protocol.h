#include <cstdint>
#include <string>
#include <vector>
#include <variant>

//source: https://stackoverflow.com/a/4956493/2388257
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
private: // to not occasionally mess with endianess
    T val;
};

using uint32bg_t = big_endian<uint32_t>;
using uint16bg_t = big_endian<uint16_t>;
using uint = unsigned int;

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
    MECHANISM = 2,
    NAME      = 3,
    TIMESTAMP = 4
};

/* a tlv_unit value, can be used with bitmask */
enum TLV_VAL: uint16_t {
    FEATURE_NONE        = 0,
    FEATURE_TLS         = 1,
    FEATURE_COMPRESSION = 2
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
    std::vector<uint8_t>  val;

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
        //todo: https://github.com/USCiLab/cereal/issues/453#issuecomment-349207696
        //for now let's stick to half-assed check.
        static const unsigned _500MB = 1024 * 1024 * 500;
        if (val_sz > _500MB)
            throw("suspiciously big msg; half-assed protection is activated!");
        val = std::vector<uint8_t>(val_sz);
        for(unsigned i = 0; i < val_sz; ++i)
            archive(val[i]);
    }

    tlv_unit(){}
    tlv_unit(const tlv_unit& u): type(u.type), val(u.val) {
        if (is_val_sz32())
            val_sz32 = u.val_sz32;
        else
            val_sz16 = u.val_sz16;
    }
    // tlv_unit(uint16_t t, uint16_t sz): type(t), val_sz16(sz) {}
    // tlv_unit(uint16_t t, uint32_t sz): type(t), val_sz32(sz) {}
    tlv_unit(uint16_t t, std::vector<uint8_t> vec): type(t), val(vec) {
        if (is_val_sz32())
            val_sz32 = vec.size();
        else
            val_sz16 = vec.size();
    }

    bool is_val_sz32 () const { return type.get() & (1 << 15);}

    // Deserialized size
    uint size() {
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

    /* The most significant bit of a message type value is reserved. The allowable
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
    uint32bg_t block_sz;
    std::vector<tlv_unit> block;

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
        for (long int i = block_sz.get(); i >= 0;) {
            try {archive(u);} catch(...) {
                fputs("wrn: a tlv_unit wasn't deserialized\n", stderr);
                break;
            }
            block.push_back(u);
            i -= u.size();
        }
    }

    // constructor without block_sz argument
    tlv_packet_data() {}
    tlv_packet_data(tlv_packet_header h, tlv_flags flgs, tlv_family fam,
                    uint16bg_t msg_t, uint32bg_t seq, std::vector<tlv_unit> blck):
        head(h), flags(flgs), family(fam), msg_type(msg_t),
        sequence(seq), block_sz(blck.size()), block(blck) {}

    // *unsafe* helpers
    uint16_t uint16_val_at(uint unit_i) const {
        return ((uint16bg_t*)block[unit_i].val.data())->get();
    }
    uint szval_at(uint unit_i) const {
        const tlv_unit& u = block[unit_i];
        return (u.is_val_sz32())? u.val_sz32.get() : u.val_sz16.get();
    }
};

const uint8_t magic = 0x6f; // tlv_packet::magic should always be equal to it

void print_tlv_packet_data(const tlv_packet_data& h);
void print_tlv_packet_version(const tlv_packet_version& v);
void print_tlv_packet(const uint8_t p[], uint tlv_sz);
const std::string show_tlv_packet(const uint8_t p[], uint tlv_sz);
const std::string show_tlv_unit(const uint8_t d[], long int d_sz, uint indent_offset);
const std::string to_hex(uint8_t* arr, uint sz_arr);

// templates can't be exported, so we have to restort to ugly hacks
std::vector<uint8_t> serialize(const tlv_unit&);
std::vector<uint8_t> serialize(const tlv_packet_data&);
std::vector<uint8_t> serialize(const tlv_packet_version&);
std::vector<uint8_t> serialize(const uint32bg_t&);
std::vector<uint8_t> serialize(const uint16bg_t&);

std::variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const uint8_t dat[], uint sz_dat);
std::variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const std::vector<uint8_t>& dat);
std::vector<tlv_unit> deserialize_units(const uint8_t dat[], long int sz_dat);
