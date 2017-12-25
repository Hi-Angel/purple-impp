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

// please, keep Cereal out of project headers as it noticably slows down compilation
#include <cereal/archives/binary.hpp>
#include <variant>
#include <vector>
#include "protocol.h"

using namespace std;

using nothing = std::monostate;

// Cereal uses an odd naming convention, so here's a mnemonic: apparently
// "OutputArchive" implies writing *to* stream, "InputArchive" is *from*.  A "stream"
// is just an IR.

template<typename T>
const stringstream class_to_ss(const T& myclass) {
    stringstream ss(ios::binary | ios::out | ios::in);
    cereal::BinaryOutputArchive to_ss = {ss};
    to_ss(myclass);
    return ss;
}

template<typename T>
const vector<uint8_t> serialize(const T& t) {
    const stringstream ss = class_to_ss(t);
    const string& s = ss.str();
    return { s.begin(), s.end() };
}

template<typename T>
variant<T, nothing> deserialize(const uint8_t dat[], uint sz_dat) {
    stringstream ss(ios::binary | ios::out | ios::in);
    cereal::BinaryOutputArchive arr_to_ss = {ss};
    arr_to_ss(cereal::binary_data(dat, sz_dat));

    cereal::BinaryInputArchive ss_to_MyClass(ss);
    T t;
    try {ss_to_MyClass(t);} catch(cereal::Exception) {
        return nothing{};
    }
    return {t};
}

variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const uint8_t dat[], uint sz_dat) {
    variant head = deserialize<tlv_packet_header>(dat, sz_dat);
    if (holds_alternative<nothing>(head))
        return {"couldn't deserialize packet header"};
    switch (get<tlv_packet_header>(head).channel) {
        case tlv_packet_header::version: {
            variant version = deserialize<tlv_packet_version>(dat, sz_dat);
            // ternary doesn't support constructors
            if (holds_alternative<nothing>(version))
                return {"failed deserializing packet_version"};
            else
                return get<tlv_packet_version>(version);
        }
        case tlv_packet_header::tlv: {
            variant dat_packet = deserialize<tlv_packet_data>(dat, sz_dat);
            // ternary doesn't support constructors
            if (holds_alternative<nothing>(dat_packet))
                return {"failed deserializing packet_data"};
            else
                return get<tlv_packet_data>(dat_packet);
        }
        default:
            return {"unknown packet channel, ignoring!"};
    }
}
variant<tlv_packet_data,tlv_packet_version,std::string> deserialize_pckt(const std::vector<uint8_t>& dat) {
    return deserialize_pckt(dat.data(), dat.size());
}

// Deserializes an array of tlv_units. Note: if there's a unit with not enough data,
// it'd get ignored for now.
vector<tlv_unit> deserialize_units(const uint8_t dat[], uint sz_dat) {
    std::vector<tlv_unit> ret;
    long int sz_left = sz_dat;
    do {
        variant u = deserialize<tlv_unit>(dat, sz_left);
        if (holds_alternative<nothing>(u))
            return ret;
        ret.push_back(get<tlv_unit>(u));
        sz_left -= get<tlv_unit>(u).size();
        dat     += get<tlv_unit>(u).size();
        assert(sz_left >= 0); // otherwise it's buffer overflow
    } while(sz_left >= 0);
    return ret;
}

// templates can't be exported, so we have to resort to dirty hacks
#define SERIALIZE(type) std::vector<uint8_t> serialize(const type& t) { return serialize<type>(t); }
SERIALIZE(tlv_unit)
SERIALIZE(tlv_packet_data)
SERIALIZE(tlv_packet_version)
SERIALIZE(uint32bg_t)
SERIALIZE(uint16bg_t)
