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
#include "protocol.h"
#include "utils.h"
#include <cereal/archives/binary.hpp>
#include <optional>
#include <variant>
#include <vector>

using namespace std;

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
optional<T> deserialize(const uint8_t dat[], uint sz_dat) {
    stringstream ss(ios::binary | ios::out | ios::in);
    cereal::BinaryOutputArchive arr_to_ss = {ss};
    arr_to_ss(cereal::binary_data(dat, sz_dat));

    cereal::BinaryInputArchive ss_to_MyClass(ss);
    T t;
    try {ss_to_MyClass(t);} catch(const cereal::Exception&) {
        return nullopt;
    }
    return t;
}

using MaybePacket = variant<tlv_packet_data,tlv_packet_version,std::string>;

MaybePacket deserialize_pckt(const uint8_t dat[], uint sz_dat) {
    optional<tlv_packet_header> mb_head = deserialize<tlv_packet_header>(dat, sz_dat);
    if (!mb_head)
        return {"couldn't deserialize packet header"};
    switch (mb_head.value().channel) {
        case tlv_packet_header::version: {
            optional mb_version = deserialize<tlv_packet_version>(dat, sz_dat);
            return (mb_version)? mb_version.value()
                : MaybePacket{"failed deserializing packet_version"};
        }
        case tlv_packet_header::tlv: {
            optional mb_dat_pckt = deserialize<tlv_packet_data>(dat, sz_dat);
            return (mb_dat_pckt)? mb_dat_pckt.value()
                : MaybePacket{"failed deserializing packet_data"};
        }
        default:
            return {"unknown packet channel, ignoring!"};
    }
}
MaybePacket deserialize_pckt(const std::vector<uint8_t>& dat) {
    return deserialize_pckt(dat.data(), dat.size());
}

// Deserializes an array of tlv_units. Note: if there's a unit with not enough data,
// it'd get ignored for now.
vector<tlv_unit> deserialize_units(const uint8_t dat[], uint sz_dat) {
    std::vector<tlv_unit> ret;
    long int sz_left = sz_dat;
    do {
        optional<tlv_unit> mb_unit = deserialize<tlv_unit>(dat, sz_left);
        if (!mb_unit)
            return ret;
        ret.push_back(mb_unit.value());
        sz_left -= mb_unit.value().size();
        dat     += mb_unit.value().size();
        assert(sz_left >= 0); // otherwise it's buffer overflow
    } while(sz_left >= 0);
    return ret;
}

// templates can't be exported, so we have to resort to dirty hacks
#define DECL_SERIALIZE(type) std::vector<uint8_t> serialize(const type& t) { return serialize<type>(t); }
DECL_SERIALIZE(tlv_unit)
DECL_SERIALIZE(tlv_packet_data)
DECL_SERIALIZE(tlv_packet_version)
DECL_SERIALIZE(uint32bg_t)
DECL_SERIALIZE(uint16bg_t)
