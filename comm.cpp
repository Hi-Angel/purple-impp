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

#include <debug.h>
#include <unistd.h>
#include "comm.h"
#include "utils.h"

using namespace std;

bool is_global_err(uint16_t err) {
    return !(err & 0x8000);
}

void impp_close(PurpleConnection *conn, const string description) {
    int errno1 = errno;
    purple_debug_info("impp", "impp closing connection\n");
    IMPPConnectionData *impp = (IMPPConnectionData*)purple_connection_get_protocol_data(conn);
    impp->comm_database.clear();
    impp->recvd.clear();
    impp->send_queue.clear();
    string err = (!description.empty())? description.c_str()
        : (errno1 == 0)? "Server closed connection"
        : string{"Lost connection with "} + g_strerror(errno1);
    auto reason = (conn->wants_to_die)? PURPLE_CONNECTION_ERROR_OTHER_ERROR
        : PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
    purple_connection_error_reason(conn, reason, err.c_str());
    purple_ssl_close(impp->ssl);
    close(impp->impp_tcp); // todo: shall I? Does pidgin do the same?
    impp->conn = 0;
    impp->ssl = 0;
}

void impp_close(PurpleConnection *conn) {
    impp_close(conn, "");
}

// handles error, like figures if connection properties needs to be updated or
// closed. Returns description of situation if there's anything to print or empty
// string otherwise.
string handle_error(const tlv_packet_data& pckt, PurpleConnection *conn) {
    assert(pckt.get_block()[0].get_val().size() == 2);
    uint16_t err = pckt.uint16_val_at(0);
    string err_desc = show_tlv_error(pckt.family, err);
    if (is_global_err(err))
        switch (err) {
            case GLOBAL::SUCCESS:             return "";
            case GLOBAL::SERVICE_UNAVAILABLE:
                impp_close(conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_CONNECTION:
                impp_close(conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_STATE:
                impp_close(conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_TLV_FAMILY:  return err_desc;
            case GLOBAL::INVALID_TLV_LENGTH:  return err_desc;
            case GLOBAL::INVALID_TLV_VALUE:   return err_desc;
            default:
                impp_close(conn, err_desc);
                return err_desc;
        }
    switch(pckt.family.get()) {
        case tlv_packet_data::stream: switch (err){
            case STREAM::FEATURE_INVALID:        return err_desc;
            case STREAM::MECHANISM_INVALID:      return err_desc;
            case STREAM::AUTHENTICATION_INVALID:
                impp_close(conn, err_desc);
                return err_desc;
            default:
                impp_close(conn, err_desc);
                return err_desc;
        }
        case tlv_packet_data::device:switch (err) {
            case DEVICE::CLIENT_INVALID:
                impp_close(conn, err_desc);
                return err_desc;
            case DEVICE::DEVICE_COLLISION:
                impp_close(conn, err_desc);
                return err_desc;
            case DEVICE::TOO_MANY_DEVICES:
                impp_close(conn, err_desc);
                return err_desc;
            case DEVICE::DEVICE_BOUND_ELSEWHERE:
                impp_close(conn, err_desc);
                return err_desc;
            default:
                impp_close(conn, err_desc);
                return err_desc;
        }
        case tlv_packet_data::lists:       // todo: fall through
        case tlv_packet_data::im:          // todo: fall through
        case tlv_packet_data::presence:    // todo: fall through
        case tlv_packet_data::avatar:      // todo: fall through
        case tlv_packet_data::group_chats: // todo: fall through
        default:
            impp_close(conn, err_desc);
            return err_desc;
    }
}

// enqueues and sends packets
size_t impp_send_tls(tlv_packet_data* in, IMPPConnectionData& impp) {
    if (!impp.comm_database.empty()) {
        if (in || !impp.send_queue.empty()) {
            // todo: guard the data with mutices if multiple threads involved
            tlv_packet_data pckt = (in)? *in : pop_front(impp.send_queue);
            pckt.sequence = impp.next_seq++;
            const std::vector<uint8_t> dat_pckt = serialize(pckt);
            impp.comm_database[pckt.sequence.get()] = {};
            return purple_ssl_write(impp.ssl, dat_pckt.data(), dat_pckt.size());
        }
    } else {
        purple_debug_info("queue_next: some packets still unanswered\n");
        if (in)
            impp.send_queue.push_back(*in);
    }
    return 0;
}

// lack of the counterpart to impp_send_tls is because making it a separate function
// results in too much boilerplate
void handle_incoming(gpointer in, PurpleSslConnection *ssl, PurpleInputCondition) {
    purple_debug_info("impp", "handle_incoming called\n");
    IMPPConnectionData& impp = *((IMPPConnectionData*)in);
    std::vector<uint8_t>& buf = impp.recvd;
    do {
        const uint old_sz = buf.size(), toread = 1024;
        buf.resize(old_sz + toread);
        int bytes = purple_ssl_read(ssl, &buf[0], toread);
        if (bytes <= 0) {
            int errno1 = errno;
            buf.resize(old_sz);
            purple_debug_info("impp", ("wrn: bytes recvd " + to_string(bytes) + "\n").c_str());
            if (errno1 == EAGAIN)
                return;
            else {
                impp_close(impp.conn);
                return;
            }
        }
        if ((uint)bytes != toread) {
            buf.resize(old_sz + (uint)bytes);
            break;
        }
    } while (true);
    // if deserializeble, process and clear input vector
    variant<tlv_packet_data,tlv_packet_version,string> maybepckt = deserialize_pckt(buf.data(), buf.size());
    if (holds_alternative<string>(maybepckt)) {
        string err = "can't deserialize incoming pckt: " + get<string>(maybepckt) + "\n";
        purple_debug_info("impp", err.c_str());
        return;
        /* todo: assume for now not all data came. In the future however it's worth
         * making a routine heuristic that gonna search the data for magic byte and
         * try deserializing it — it would protect us from a broken packet. For now
         * receiving a packet with wrong size might be fatal to whole connection */
    } else if (holds_alternative<tlv_packet_version>(maybepckt)) {
        purple_debug_info("impp", "wrn: version in the middle of a session\n");
        buf.erase(buf.begin(), buf.begin() + sizeof(tlv_packet_version));
        return;
    } // else tlv_packet_data
    const tlv_packet_data& pckt = get<tlv_packet_data>(maybepckt);
    buf.erase(buf.begin(), buf.begin() + pckt.curr_pckt_sz());
    purple_debug_info(show_tlv_packet_data(pckt, 0) + "\n");

    switch (pckt.flags.get()) {
        case tlv_packet_data::request:
            purple_debug_info("impp", "wrn: request from a server, what could that be?\n");
            return;
        case tlv_packet_data::response:
            if (!impp.comm_database.erase(pckt.sequence.get()))
                purple_debug_info("impp", "wrn: response to a packet we never sent\n");
            else
                impp_send_tls(0, impp);
            return;
        case tlv_packet_data::indication:
            purple_debug_info("impp", "todo: indication\n");
            return;
        case tlv_packet_data::error: {
            string err = handle_error(pckt, impp.conn);
            if (!err.empty())
                purple_debug_info("error " + err);
            return;
        }
        case tlv_packet_data::extension:
            purple_debug_info("impp", "wrn: extension request from a server, what could that be?\n");
            return;
    }
}
