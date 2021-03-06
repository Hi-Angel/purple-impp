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
#include <deque>
#include "protocol.h"

struct SentRecord {
    /* std::unique_ptr<tlv_packet_data> maybe_packet; */
};

struct IMPPConnectionData {
    PurpleConnection *conn;
    int impp_tcp;

    // key = sequence number
    std::unordered_map<uint32_t, SentRecord> ack_waiting;

    // pings has a separate queue because judging by server's behavior pings not
    // necessarily has to be invalidated by ping-response, but at least also by
    // indications
    std::vector<uint32_t> ping_waiting;
    PurpleSslConnection *ssl;

    // scratch buf for input data. Performance-wise it supposed to leave allocated
    // space untouched most of times on shrink, hence just do resize() instead of
    // storing a uint for tracking the size.
    // todo: performance-wise std::deque is better, but unclear how to deal with
    // uncontiguous memory, nor a priority
    std::vector<uint8_t> recvd;

    // server freaks out upon getting packets without waiting for reply. Queue them.
    std::deque<tlv_packet_data> send_queue;
    uint32_t next_seq;
};

bool is_global_err(uint16_t err);
void impp_close(PurpleConnection *conn);
void impp_close(PurpleConnection *conn, const std::string reason);
// enqueues and sends packets
size_t impp_send_tls(const tlv_packet_data* in, IMPPConnectionData& impp);
void handle_incoming(gpointer in, PurpleSslConnection *ssl, PurpleInputCondition);
int impp_send_im(PurpleConnection *conn, const char *to, const char *msg,
                 PurpleMessageFlags flags);
void impp_send_ping(PurpleConnection* conn);

#endif //COMM_H
