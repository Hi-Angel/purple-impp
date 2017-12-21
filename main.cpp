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

//TODO
// 1. rename functions, variables — many of them have "default" names due to me
// trying to make a minimal working prototype
// 2. server is hardcoded, I need to construct some "DNS SRV lookup", whatever it is.
// 3. whatever todos are in the code.

#include <glib.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <cstring>

#define PURPLE_PLUGINS

#include <notify.h>
#include <network.h>
#include <plugin.h>
#include <version.h>
#include <debug.h>
#include <proxy.h>
#include <sys/socket.h>
#include <utility>
#include <sslconn.h>
#include "protocol.h"
#include "utils.h"
#include "comm.h"
#include "common-consts.h"

using namespace std;

extern "C" {

char Formats[] = "png,jpg,gif";
const char DEFAULT_HOME_HOST[] = "_tcp.trillian.im";
const char TEST_TRILLIAN_HOST[] = "74.201.34.42";
const uint TEST_TRILLIAN_PORT = 3158;
const char PRPL_ACCOUNT_OPT_HOME_SERVER[] = "home_server";
const uint min_pckt_sz = sizeof(tlv_packet_version);

/**
 * Called to get the icon name for the given buddy and account.
 *
 * If buddy is NULL and the account is non-NULL, it will return the
 * name to use for the account's icon. If both are NULL, it will
 * return the name to use for the protocol's icon.
 *
 * For now, everything just uses the 'default' icon.
 */
static const char *impp_list_icon(PurpleAccount *acct, PurpleBuddy *buddy)
{
    return "default";
}

static void impp_destroy(PurplePlugin *plugin) {
    purple_debug_info("impp", "shutting down\n");
}

/**
 * Called to get a list of the PurpleStatusType which are valid for this account
 *
 * (currently, we don't really implement any, but we have to return something
 * here)
 */
static GList *impp_status_types(PurpleAccount *acct)
{
    purple_debug_info("impp", "impp_status_types\n");
    GList *types = NULL;
    PurpleStatusType *type;

    type = purple_status_type_new(PURPLE_STATUS_OFFLINE, "Offline", NULL, TRUE);
    types = g_list_prepend(types, type);

    type = purple_status_type_new(PURPLE_STATUS_AVAILABLE, "Online", NULL, TRUE);
    types = g_list_prepend(types, type);

    return types;
}

/* Make conn and data to point each to another */
void impp_connection_new(PurpleConnection *conn) {
    g_assert(purple_connection_get_protocol_data(conn) == NULL);
    IMPPConnectionData *data = g_new0(IMPPConnectionData, 1);
    data->conn = conn;
    purple_connection_set_protocol_data(conn, data);
}
// amount can be equal to zero.
// returns -1 on error (keeps errno set), 0 on timeout, and 1 when amount of bytes
// received. Note, there's: no way to know a number of received bytes upon
// timeout. It can be introduced, but for now it's okay.
int try_recv(int fd, uint8_t* buf, uint amount, int msec) {
    if (amount == 0)
        return 1;
    struct pollfd pfd = {fd: fd, events: POLLIN | POLLPRI, revents: 0};
    int ret = poll(&pfd, 1, msec);
    if (ret <= 0)
        return ret;
    ret = recv(fd, (char*)buf, amount, MSG_NOSIGNAL);
    return (ret < 0)? ret
        : ((uint)ret == amount)? 1
        : try_recv(fd, buf, amount - (uint)ret, msec);
}

// returns units, and int — 1 for okay, 0 for timeout, -1 for error (see errno)
pair<int,vector<tlv_unit>> recv_units(int fd, uint bytes, int msec) {
    std::vector<tlv_unit> units;
    for (uint recvd = 0; recvd < bytes;) {
        const uint min_body = sizeof(tlv_unit::type) + sizeof(tlv_unit::val_sz16),
            max_body = sizeof(tlv_unit::type) + sizeof(tlv_unit::val_sz32);
        vector<uint8_t> buf = vector<uint8_t>(max_body);
        auto recv1 = [fd,msec,&buf](uint offset, uint sz) -> int { return try_recv(fd, &buf[0] + offset, sz, msec); };
        int ret = recv1(0, min_body);
        if (ret <= 0)
            return {ret, units};
        if (((tlv_unit*)(&buf[0]))->is_val_sz32()) {
            ret = recv1(min_body, max_body - min_body);
            if (ret <= 0)
                return {ret, units};
            buf.resize(max_body + ((tlv_unit*)(&buf[0]))->val_sz32.get());
            ret = recv1(max_body, ((tlv_unit*)(&buf[0]))->val_sz32.get());
            if (ret <= 0)
                return {ret, units};
        } else {
            buf.resize(min_body + ((tlv_unit*)(&buf[0]))->val_sz16.get());
            ret = recv1(min_body, ((tlv_unit*)(&buf[0]))->val_sz16.get());
            if (ret <= 0)
                return {ret, units};
        }
        std::vector<tlv_unit> unit = deserialize_units(buf.data(), buf.size());
        assert(unit.size() == 1);
        units += unit;
        recvd += buf.size();
        assert(recvd <= bytes);
    }
    return {1, units};
}

const std::string impp_request_version(int fd) {
    send(fd, &templ_version_request, sizeof(templ_version_request), MSG_NOSIGNAL);
    uint8_t buf[sizeof(templ_version_request)];
    switch(try_recv(fd, buf, sizeof(buf), 30000)) {
        case -1:
            return strerror_newl(errno);
        case 0:
            return "version_request timed out\n";
        default:
            break;
    }
    if (memcmp(&templ_version_request, (char*)buf, sizeof(templ_version_request))) {
        return "wrn: version_request reply differs, content:\n"
            + show_tlv_packet(buf, sizeof(buf)) + "\n";
    }
    return "";
}

std::string impp_comm_feature_set(int fd) {
    const tlv_unit unit = { type: STREAM::FEATURES,
                            val: serialize(uint16bg_t{STREAM::FEATURE_TLS})};
    tlv_packet_data packet = { {magic: magic, channel: tlv_packet_header::tlv},
                                flags: tlv_packet_data::request, family: tlv_packet_data::stream,
                                msg_type: STREAM::FEATURES_SET, sequence: 0, block: {unit} };
    const std::vector<uint8_t> dat = serialize(packet);
    send(fd, dat.data(), dat.size(), MSG_NOSIGNAL);
    uint8_t buf[dat.size()];
    switch(try_recv(fd, buf, sizeof(buf), 30000)) {
        case -1:
            return strerror_newl(errno);
        case 0:
            return "feature_set timed out\n";
        default:
            break;
    }
    auto reply = deserialize_pckt(buf, sizeof(buf));
    std::string err = (std::holds_alternative<std::string>(reply))? std::get<std::string>(reply)
        : (std::holds_alternative<tlv_packet_version>(reply))? "version instead of data"
        : (std::get<tlv_packet_data>(reply).get_block().size() != 1)? "unexpected number of units"
        : (std::get<tlv_packet_data>(reply).szval_at(0) != sizeof(uint16bg_t))? "unexpected amount of data"
        : "";
    if (!err.empty()) {
        return err + "\n";
    }
    if (std::get<tlv_packet_data>(reply).uint16_val_at(0) != STREAM::FEATURE_TLS) {
        return "wrn: feature_set unexpected value: "
            + std::to_string(std::get<tlv_packet_data>(reply).uint16_val_at(0)) + "\n";
    }
    return "";
}

static void query_caps(IMPPConnectionData* impp) {
    tlv_packet_data req = templ_basic_request;
    req.family   = tlv_packet_data::lists;
    req.msg_type = LISTS::GET;
    impp_send_tls(req, impp);
    req.family   = tlv_packet_data::group_chats;
    req.msg_type = GROUP_CHATS::MESSAGE_SEND;
    impp_send_tls(req, impp);
    req.family   = tlv_packet_data::im;
    req.msg_type = IM::OFFLINE_MESSAGES_GET;
    impp_send_tls(req, impp);
    req.family   = tlv_packet_data::presence;
    req.msg_type = PRESENCE::GET;
    impp_send_tls(req, impp);
}

void impp_on_tls_connect(gpointer data, PurpleSslConnection *ssl, PurpleInputCondition) {
    purple_debug_info("impp", "SSL connection established\n");
    IMPPConnectionData* t_data = ((IMPPConnectionData*)data);
    t_data->comm_database = new unordered_map<uint32_t, SentRecord>{};
    t_data->ssl = ssl;
    t_data->next_seq = 100;
    purple_ssl_input_add(ssl, handle_incoming, t_data);

    const char* name = purple_account_get_username(t_data->conn->account);
    const char* pass = purple_account_get_password(t_data->conn->account);
    tlv_packet_data auth = templ_authorize;
    auth.set_tlv_val(1, vector<uint8_t>{name, name + strlen(name)});
    auth.set_tlv_val(2, vector<uint8_t>{pass, pass + strlen(pass)});
    impp_send_tls(auth, t_data);
    tlv_packet_data client_info = templ_client_info;
    impp_send_tls(client_info, t_data);

    query_caps(t_data);
    purple_debug_info("impp", "impp_on_tls_connect finished\n");
}

void impp_tcp_established_hook(gpointer data, gint src, const gchar *error_message) {
    std::string ret ="tcp-connection";
    if (error_message) {
        ret += error_message;
        purple_debug_info("impp", (ret + "\n").c_str());
        return;
    }
    IMPPConnectionData* con_dat = ((IMPPConnectionData*)data);
    con_dat->impp_tcp = src;
    purple_debug_info("impp", (ret + " is in progress\n").c_str());
    // Negotiate an IMPP protocol version
    ret = impp_request_version(src);
    if (!ret.empty()) {
        purple_debug_info("impp", ret.c_str());
        impp_close(con_dat->conn, ret);
        return;
    }
    ret = impp_comm_feature_set(src);
    if (!ret.empty()) {
        impp_close(con_dat->conn, ret);
        purple_debug_info("impp", ret.c_str());
        return;
    }
    purple_debug_info("impp", "tcp-connection established, configuring TLS\n");
    auto ssl_err = [](PurpleSslConnection*, PurpleSslErrorType, gpointer) {
            purple_debug_info("impp", "TLS error\n"); //todo tell exact error
        };
    purple_ssl_connect_with_host_fd(con_dat->conn->account, src, impp_on_tls_connect,
                                    ssl_err,
                                    TEST_TRILLIAN_HOST, data);
}

void impp_connection_start_login(PurpleConnection *conn) {
    PurpleAccount *acct = conn->account;
    IMPPConnectionData *data = (IMPPConnectionData*)purple_connection_get_protocol_data(conn);
    if (!purple_proxy_connect(0, acct, TEST_TRILLIAN_HOST,
                              TEST_TRILLIAN_PORT, impp_tcp_established_hook, data)) {
        purple_debug_info("impp", "purple_proxy_connect error\n");
        impp_close(conn, "purple_proxy_connect error\n");
        return; //todo: perror?
    }
}

/**
 * Start the connection to a impp account
 */
void impp_login(PurpleAccount *acc)
{
    purple_debug_info("impp", "impp login\n");
    PurpleConnection *conn = purple_account_get_connection(acc);
    impp_connection_new(conn);
    impp_connection_start_login(conn);

    // purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing",
    //     acct, PURPLE_CALLBACK(imppprpl_conv_send_typing), conn);

    // conn->flags |= PURPLE_CONNECTION_HTML;
}

static PurplePluginProtocolInfo prpl_info =
{
    OPT_PROTO_IM_IMAGE, // | OPT_PROTO_CHAT_TOPIC | OPT_PROTO_UNIQUE_CHATNAME,
    0,               /* user_splits, initialized in impp_init() */
    0,               /* protocol_options, initialized in impp_init() */
    {   /* icon_spec, a PurpleBuddyIconSpec */
        Formats,                   /* format */
        0,                               /* min_width */
        0,                               /* min_height */
        128,                             /* max_width */
        128,                             /* max_height */
        10000,                           /* max_filesize */
        PURPLE_ICON_SCALE_DISPLAY,       /* scale_rules */
    },
    impp_list_icon,                   /* list_icon */
    0,                                /* list_emblem */
    0,                                /* status_text */
    0,                                /* tooltip_text */
    impp_status_types,                /* status_types */
    0,                                /* blist_node_menu */
    0, //impp_chat_info,              /* chat_info */
    0, //impp_chat_info_defaults,     /* chat_info_defaults */
    impp_login,                       /* login */
    impp_close,                       /* close */
    0,                                /* send_im */
    0,                                /* set_info */
    0,                                /* send_typing */
    0,                                /* get_info */
    0,                                /* set_status */
    0,                                /* set_idle */
    0,                                /* change_passwd */
    0,                                /* add_buddy */
    0,                                /* add_buddies */
    0,                                /* remove_buddy */
    0,                                /* remove_buddies */
    0,                                /* add_permit */
    0,                                /* add_deny */
    0,                                /* rem_permit */
    0,                                /* rem_deny */
    0,                                /* set_permit_deny */
    0, //impp_join_chat,              /* join_chat */
    0, //impp_reject_chat,            /* reject_chat */
    0, //impp_get_chat_name,          /* get_chat_name */
    0, //impp_chat_invite,            /* chat_invite */
    0, //impp_chat_leave,             /* chat_leave */
    0,                                /* chat_whisper */
    0, //impp_chat_send,              /* chat_send */
    0,                                /* keepalive */
    0,                                /* register_user */
    0,                                /* get_cb_info */
    0,                                /* get_cb_away */
    0,                                /* alias_buddy */
    0,                                /* group_buddy */
    0,                                /* rename_group */
    0,                                /* buddy_free */
    0,                                /* convo_closed */
    0,                                /* normalize */
    0,                                /* set_buddy_icon */
    0,                                /* remove_group */
    0, //impp_get_cb_real_name,       /* get_cb_real_name */
    0,                                /* set_chat_topic */
    0,                                /* find_blist_chat */
    0,                                /* roomlist_get_list */
    0,                                /* roomlist_cancel */
    0,                                /* roomlist_expand_category */
    0,                                /* can_receive_file */
    0,                                /* send_file */
    0,                                /* new_xfer */
    0,                                /* offline_message */
    0,                                /* whiteboard_prpl_ops */
    0,                                /* send_raw */
    0,                                /* roomlist_room_serialize */
    0,                                /* unregister_user */
    0,                                /* send_attention */
    0,                                /* get_attention_types */
    sizeof(PurplePluginProtocolInfo), /* struct_size */
    0,                                /* get_account_text_table */
    0,                                /* initiate_media */
    0,                                /* get_media_caps */
    0,                                /* get_moods */
    0,                                /* set_public_alias */
    0,                                /* get_public_alias */
    0,                                /* add_buddy_with_invite */
    0                                 /* add_buddies_with_invite */
};

// struct PurplePluginInfo requires these declarations not to be const
#define DEBUGSUFFIX "9impp"
char PRPL_ID[]         = "prpl-" DEBUGSUFFIX;
char PLUGIN_NAME[]     = DEBUGSUFFIX;
char DISPLAY_VERSION[] = "1.0";
char SUMMARY[]         = "Trillian IMPP Protocol Plugin";
char DESCRIPTION[]     = "Trillian IMPP Protocol Plugin";
char AUTHOR[]          = "Konstantin Kharlamov <hi-angel@yandex.ru>";
char HOMEPAGE[]        = "https://www.impp.im/";

static PurplePluginInfo info =
{
    PURPLE_PLUGIN_MAGIC,     /* magic */
    PURPLE_MAJOR_VERSION,    /* major_version */
    PURPLE_MINOR_VERSION,    /* minor_version */
    PURPLE_PLUGIN_PROTOCOL,  /* type */
    0,                       /* ui_requirement */
    0,                       /* flags */
    0,                       /* dependencies */
    PURPLE_PRIORITY_DEFAULT, /* priority */
    PRPL_ID,                 /* id */
    PLUGIN_NAME,             /* name */
    DISPLAY_VERSION,         /* version */
    SUMMARY,                 /* summary */
    DESCRIPTION,             /* description */
    AUTHOR,                  /* author */
    HOMEPAGE,                /* homepage */
    0,                       /* load */
    0,                       /* unload */
    impp_destroy,        /* destroy */
    0,                       /* ui_info */
    &prpl_info,              /* extra_info */
    0,                       /* prefs_info */
    0,                       /* actions */
    0,                       /* padding... */
    0,
    0,
    0,
};


static void
init_plugin(PurplePlugin *plugin) {
    purple_debug_info("impp", "starting up\n");
}

PURPLE_INIT_PLUGIN(¯\_(ツ)_/¯, init_plugin, info);

} // extern "C"
