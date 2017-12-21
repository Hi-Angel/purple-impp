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

#ifndef COMM_H
#define COMM_H

#include <memory>
#include <unordered_map>
#include <connection.h>
#include <string>
#include "protocol.h"

struct SentRecord {
    /* std::unique_ptr<tlv_packet_data> maybe_packet; */
};

struct IMPPConnectionData {
    PurpleConnection *conn;
    int impp_tcp;

    // key = sequence number
    std::unordered_map<uint32_t, SentRecord>* comm_database = 0;
    PurpleSslConnection *ssl;

    // scratch buf for input data. Performance-wise it supposed to leave allocated
    // space untouched most of times on shrink, hence just do resize() instead of
    // storing a uint for tracking the size.
    // todo: performance-wise std::dequeue is better, but unclear how to deal with
    // uncontiguous memory, nor a priority
    std::vector<uint8_t> recvd;
    uint32_t next_seq;
};

bool is_global_err(uint16_t err);
void impp_close(PurpleConnection *conn);
void impp_close(PurpleConnection *conn, const std::string reason);
size_t impp_send_tls(tlv_packet_data& pckt, IMPPConnectionData* impp);
void handle_incoming(gpointer in, PurpleSslConnection *ssl, PurpleInputCondition);

#endif //COMM_H
