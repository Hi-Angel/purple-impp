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
#include <numeric>
#include <blist.h>
#include <ctime>
#include <server.h>
#include "comm.h"
#include "utils.h"
#include "common-consts.h"

using namespace std;

bool is_global_err(uint16_t err) {
    return !(err & 0x8000);
}

void impp_close(PurpleConnection *conn, const string description) {
    int errno1 = errno;
    IMPPConnectionData *impp = (IMPPConnectionData*)purple_connection_get_protocol_data(conn);
    if (!impp->conn) // after closing pidgin calls it again, ignore it
        return;
    purple_debug_info("impp", "impp closing connection\n");
    impp->ack_waiting.clear();
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
static string handle_error(const tlv_packet_data& pckt, IMPPConnectionData& impp) {
    assert(pckt.get_block()[0].get_val().size() == 2);
    uint16_t err = pckt.uint16_val_at(0);
    string err_desc = show_tlv_error(pckt.family, err);
    if (is_global_err(err))
        switch (err) {
            case GLOBAL::SUCCESS:             return "";
            case GLOBAL::SERVICE_UNAVAILABLE:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_CONNECTION:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_STATE:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case GLOBAL::INVALID_TLV_FAMILY:  return err_desc;
            case GLOBAL::INVALID_TLV_LENGTH:  return err_desc;
            case GLOBAL::INVALID_TLV_VALUE:   return err_desc;
            default:
                impp_close(impp.conn, err_desc);
                return err_desc;
        }
    switch(pckt.family.get()) {
        case tlv_packet_data::stream: switch (err){
            case STREAM::FEATURE_INVALID:        return err_desc;
            case STREAM::MECHANISM_INVALID:      return err_desc;
            case STREAM::AUTHENTICATION_INVALID:
                impp_close(impp.conn, err_desc);
                return err_desc;
            default:
                impp_close(impp.conn, err_desc);
                return err_desc;
        }
        case tlv_packet_data::device: switch (err) {
            case DEVICE::CLIENT_INVALID:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case DEVICE::DEVICE_COLLISION:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case DEVICE::TOO_MANY_DEVICES:
                impp_close(impp.conn, err_desc);
                return err_desc;
            case DEVICE::DEVICE_BOUND_ELSEWHERE:
                impp_close(impp.conn, err_desc);
                return err_desc;
            default:
                impp_close(impp.conn, err_desc);
                return err_desc;
        }
        case tlv_packet_data::lists:       // todo
            impp_close(impp.conn, err_desc);
            return err_desc;
        case tlv_packet_data::im: switch(err) {
            case IM::USERNAME_BLOCKED:     // fall through
            case IM::USERNAME_NOT_CONTACT: // fall through
            case IM::INVALID_CAPABILITY:
                if (!impp.ack_waiting.erase(pckt.sequence.get()))
                    impp_debug_info("wrn: response to a packet we never sent");
                return err_desc;
            default:
                assert(0);
                impp_debug_info("wrn: unknown im error");
                if (!impp.ack_waiting.erase(pckt.sequence.get()))
                    impp_debug_info("wrn: response to a packet we never sent");
                return err_desc;
        }
        case tlv_packet_data::presence:    // todo:
        case tlv_packet_data::avatar:      // todo:
        case tlv_packet_data::group_chats: // todo:
        default:
            impp_close(impp.conn, err_desc);
            return err_desc;
    }
}

// enqueues and sends packets
size_t impp_send_tls(const tlv_packet_data* in, IMPPConnectionData& impp) {
    // todo: guard the data with mutices if multiple threads involved
    if (in)
        impp.send_queue.push_back(*in);
    if (impp.ack_waiting.empty()) {
        if (!impp.send_queue.empty()) {
            impp_debug_info("dbg: sending next packet");
            tlv_packet_data pckt = pop_front(impp.send_queue);
            pckt.sequence = impp.next_seq++;
            const std::vector<uint8_t> dat_pckt = serialize(pckt);
            impp.ack_waiting[pckt.sequence.get()] = {};
            if (pckt.msg_type.get() == STREAM::PING)
                impp.ping_waiting.push_back(pckt.sequence.get());
            return purple_ssl_write(impp.ssl, dat_pckt.data(), dat_pckt.size());
        }
    } else {
        impp_debug_info("queue_next: packets №"
                             + accumulate(impp.ack_waiting.begin(),
                                          impp.ack_waiting.end(),
                                          string{""},
                                          [](string acc, auto i) { return acc + to_string(i.first); })
                             + " still unanswered\n");
    }
    return 0;
}

static
void show_msg_from(IMPPConnectionData& impp, string from, string msg,
                  PurpleMessageFlags flags, time_t t) {
    if (flags != PURPLE_MESSAGE_ERROR) {
        // todo: buds handling here needs to be reconsidered after contact list and
        // contact requests are implemented
        PurpleBuddy* bud = purple_find_buddy(impp.conn->account, from.c_str());
        if (!bud)
            bud = purple_buddy_new(impp.conn->account, from.c_str(), 0);
        purple_blist_add_buddy(bud, 0, 0, 0);
    }
    serv_got_im(impp.conn, from.c_str(), msg.c_str(), flags, t);
}

static
void handle_offline_msgs(const vector<tlv_unit>& batch, IMPPConnectionData& impp) {
    for(const tlv_unit& u : batch) {
        const vector<tlv_unit> msg_unit = deserialize_units(u.get_val().data(), u.get_val().size());
        uint from_i = locate_tlv_type(msg_unit, IM::FROM),
            msg_i = locate_tlv_type(msg_unit, IM::MESSAGE_CHUNK);
        if (from_i == msg_unit.size() || msg_i == msg_unit.size()) {
            assert(false);
            impp_debug_info("err: incorrect msg, ignoring");
            continue;
        }

        #define val_at(i) (msg_unit[i].get_val())
        string from = {val_at(from_i).data(), val_at(from_i).data() + val_at(from_i).size()},
            msg = {val_at(msg_i).data(), val_at(msg_i).data() + val_at(msg_i).size()};
        #undef val_at

        // todo: I dunno what's the time format they're using, not POSIX for sure.
        time_t t = 0;
        show_msg_from(impp, from, msg, PURPLE_MESSAGE_RECV, t);
        // todo: notify the server we got the msg
        impp_debug_info("dbg: offline message handled!");
    }
}

static
void handle_indication_im(const tlv_packet_data& pckt, IMPPConnectionData& impp) {
    uint from_i = locate_tlv_type(pckt.get_block(), IM::FROM),
        msg_i = locate_tlv_type(pckt.get_block(), IM::MESSAGE_CHUNK),
        cap_i = locate_tlv_type(pckt.get_block(), IM::CAPABILITY);
    if (from_i == pckt.get_block().size() || msg_i == pckt.get_block().size()
        || cap_i == pckt.get_block().size()) {
        assert(false);
        impp_debug_info("err: incorrect msg, ignoring");
        return;
    }
    #define val_at(i) (pckt.get_block()[i].get_val())
    string from = {val_at(from_i).data(), val_at(from_i).data() + val_at(from_i).size()};

    //note: indications shouldn't need a reply
    if (pckt.msg_type.get() == IM::MESSAGE_SEND) {
        switch (pckt.uint16_val_at(cap_i)) {
            case IM::CAPABILITY_IM: {
                string msg = {val_at(msg_i).data(), val_at(msg_i).data() + val_at(msg_i).size()};
                // todo: I dunno what's the time format they're using, not POSIX for sure.
                time_t t = 0;
                show_msg_from(impp, from, msg, PURPLE_MESSAGE_RECV, t);
                break;
            }
            case IM::CAPABILITY_TYPING: {
                switch (pckt.uint16_val_at(msg_i)) {
                    case IM::TYPING_STARTED:
                        serv_got_typing(impp.conn, from.c_str(), 0, PURPLE_TYPING);
                        break;
                    case IM::TYPING_STOPPED:
                        serv_got_typing_stopped(impp.conn, from.c_str());
                        break;
                    default:
                        impp_debug_info("err: unknown CAPABILITY_TYPING val, ignoring");
                }
                break;
            }
            default:
                impp_debug_info("err: unknown IM capability indication, ignoring");
        }
    }
    #undef val_at
}

// lack of the counterpart to impp_send_tls is because extracting the function
// results in too much boilerplate
void handle_incoming(gpointer in, PurpleSslConnection *ssl, PurpleInputCondition) {
    purple_debug_info("impp", "handle_incoming called\n");
    IMPPConnectionData& impp = *((IMPPConnectionData*)in);
    std::vector<uint8_t>& buf = impp.recvd;
    do {
        const uint old_sz = buf.size(), toread = 1024;
        buf.resize(old_sz + toread);
        int bytes = purple_ssl_read(ssl, &buf[old_sz], toread);
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
    impp_debug_info(show_tlv_packet_data(pckt, 0) + "\n");

    // It seems, a server can, at least, reply with indication to a ping, which sort
    // of makes sense however undocumented. So let's assume any packet as a
    // ping-reply, and hope it won't have side-effects
    for (uint32_t ping_seq : impp.ping_waiting)
        impp.ack_waiting.erase(ping_seq);
    impp.ping_waiting.clear();

    switch (pckt.flags.get()) {
        case tlv_packet_data::request:
            purple_debug_info("impp", "wrn: request from a server, what could that be?\n");
            return;
        case tlv_packet_data::response:
            if (!impp.ack_waiting.erase(pckt.sequence.get()))
                purple_debug_info("impp", "wrn: response to a packet we never sent\n");
            else
                impp_send_tls(0, impp);
            if (pckt.family.get() == tlv_packet_data::im
                && pckt.msg_type.get() == IM::OFFLINE_MESSAGES_GET)
                handle_offline_msgs(pckt.get_block(), impp);
            // else todo
            // todo: handle OFFLINE_MESSAGE at flags=lists (just a notification)
            return;
        case tlv_packet_data::indication:
            if (pckt.family.get() == tlv_packet_data::im)
                handle_indication_im(pckt, impp);
            else
                purple_debug_info("impp", "todo: indications\n");
            return;
        case tlv_packet_data::error: {
            string err = handle_error(pckt, impp);
            if (!err.empty()) {
                time_t t = time(0);
                // todo: if the error is im-specific, use the relevant tab
                serv_got_im(impp.conn, err.c_str(), err.c_str(), PURPLE_MESSAGE_ERROR, t);
                impp_debug_info("error " + err);
            }
            return;
        }
        case tlv_packet_data::extension:
            purple_debug_info("impp", "wrn: extension request from a server, what could that be?\n");
            return;
        default:
            impp_debug_info("wrn: unknown incoming flag");
            return;
    }
}

// send user msg
int impp_send_im(PurpleConnection *conn, const char *to, const char *msg,
                 PurpleMessageFlags flags) {
    IMPPConnectionData& impp = *(IMPPConnectionData*)purple_connection_get_protocol_data(conn);
    impp_debug_info("dbg: impp_send_im called");
    #define tlv_type_at(i) templ_user_msg.get_block()[i].type.get()
    assert(tlv_type_at(0)    == IM::FROM && tlv_type_at(1) == IM::TO
           && tlv_type_at(2) == IM::MESSAGE_ID && tlv_type_at(3) == IM::MESSAGE_SIZE
           && tlv_type_at(4) == IM::MESSAGE_CHUNK && tlv_type_at(5) == IM::CAPABILITY
           && tlv_type_at(6) == IM::CREATED_AT);

    tlv_packet_data pckt = templ_user_msg;
    const string from = {conn->account->username},
        to1 = {to},
        msg1 = {msg};
    uint32bg_t msg_size = msg1.size();
    pckt.set_tlv_val(0,{ from.data(),  from.data() + from.size()});
    pckt.set_tlv_val(1,{ to1.data(),   to1.data() + to1.size()});
    pckt.set_tlv_val(3,{ (uint8_t*)&msg_size, (uint8_t*)&msg_size + sizeof(msg_size)});
    pckt.set_tlv_val(4,{ msg1.data(),  msg1.data() + msg1.size()});
    // todo: CREATED_AT
    impp_send_tls(&pckt, impp);
    return 1;
}

void impp_send_ping(PurpleConnection* conn) {
    impp_debug_info("ping called");
    IMPPConnectionData& impp = *(IMPPConnectionData*)purple_connection_get_protocol_data(conn);
    tlv_packet_data ping = templ_ping;
    impp_send_tls(&ping, impp);
}
