//TODO BEFORE-UPSTREAMING:
// 1. clean up the structs
// 2. rename functions, variables — many of them have "default" names due to me trying to make a
// minimal working prototype
// 3. a lot of the code tied to bad C-style protocols, move 'em to another file
// 4. grep -rnIi matrix
// 5. server is hardcoded, I need to construct some "DNS SRV lookup", whatever it is.
// 6. rename trillian → impp in case somebody gonna write a purple web-wrapper.

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
#include "protocol.h"

#define TLV_UNITN_RET(bits)                                             \
    {                                                                   \
        packet_sz -= sizeof(tlv_unit##bits);                            \
        tlv_unit##bits* un = (tlv_unit##bits*) u->tlv_unit16or32;       \
        if (packet_sz <= 0)                                              \
            return {0, 0};                                              \
        if ((int)(un->val_sz.get()) > packet_sz)                        \
            return {0, 0};                                              \
        if (!n)                                                         \
            return {(uint8_t*)un->val, un->val_sz.get()};               \
        u = (tlv_unit*)inc_by_bytes(un, sizeof(*un) + un->val_sz.get()); \
        packet_sz -= un->val_sz.get();                                  \
    }

/* receives an array representing a packet, returns either (nth_value_pointer,
   size), or (null, undefined) if there's no nth tlv. Indexing is zero-based */
std::pair<uint8_t*, uint> tlv_nth_val(const uint8_t* packet, long int packet_sz, uint n){
    tlv_packet_data* p = (tlv_packet_data*)packet;
    packet_sz -= sizeof(tlv_packet_data);
    if (packet_sz <=  0)
        return {0, 0};
    for (tlv_unit* u = (tlv_unit*)p->block; ; --n){
        packet_sz -= sizeof(tlv_unit);
        if (packet_sz <=  0)
            return {0, 0};
        if (u->type.get() & (1 << 15))
            TLV_UNITN_RET(32)
        else
    {
        packet_sz -= sizeof(tlv_unit16);
        tlv_unit16* un = (tlv_unit16*) u->tlv_unit16or32;
        if (packet_sz <= 0)
            return {0, 0};
        if ((int)(un->val_sz.get()) > packet_sz)
            return {0, 0};
        if (!n)
            return {(uint8_t*)un->val, un->val_sz.get()};
        u = (tlv_unit*)inc_by_bytes(un, sizeof(*un) + un->val_sz.get());
        packet_sz -= un->val_sz.get();
    }
    }
}

extern "C" {

// 14 is the version of at least 6.0.0 trillian client
const tlv_packet_version version_request = {magic, tlv_packet_header::version, (uint16bg_t)14};

char Formats[] = "png,jpg,gif";
const char DEFAULT_HOME_HOST[] = "_tcp.trillian.im";
const char TEST_TRILLIAN_HOST[] = "74.201.34.42";
const uint TEST_TRILLIAN_PORT = 3158;
const uint DEBUG_PORT = 7777;
const char PRPL_ACCOUNT_OPT_HOME_SERVER[] = "home_server";

struct TrillianConnectionData {
    PurpleConnection *conn;
    int trillian_tcp;
    // it should wrap data in TSL when needed and send to trillian. Will work once I figure out how
    // to act on new data in libpurple
    int debug_tcp;
    const gchar *homeserver;      /* URL of the homeserver. Always ends in '/' */
    const gchar *user_id;         /* our full user id ("@user:server") */
    const gchar *access_token;    /* access token corresponding to our user */

};


/**
 * Called to get the icon name for the given buddy and account.
 *
 * If buddy is NULL and the account is non-NULL, it will return the
 * name to use for the account's icon. If both are NULL, it will
 * return the name to use for the protocol's icon.
 *
 * For now, everything just uses the 'default' icon.
 */
static const char *trillian_list_icon(PurpleAccount *acct, PurpleBuddy *buddy)
{
    return "default";
}


static void trillian_close(PurpleConnection *conn)
{
    purple_debug_info("trillian", "trillian closing connection\n");
    TrillianConnectionData *data = (TrillianConnectionData*)purple_connection_get_protocol_data(conn);
    close(data->trillian_tcp);
    close(data->debug_tcp);
    // todo: close connection
}

static void trillian_destroy(PurplePlugin *plugin) {
    purple_debug_info("trillian", "shutting down\n");
}

/**
 * Called to get a list of the PurpleStatusType which are valid for this account
 *
 * (currently, we don't really implement any, but we have to return something
 * here)
 */
static GList *trillian_status_types(PurpleAccount *acct)
{
    purple_debug_info("trillian", "trillian_status_types\n");
    GList *types = NULL;
    PurpleStatusType *type;

    type = purple_status_type_new(PURPLE_STATUS_OFFLINE, "Offline", NULL, TRUE);
    types = g_list_prepend(types, type);

    type = purple_status_type_new(PURPLE_STATUS_AVAILABLE, "Online", NULL, TRUE);
    types = g_list_prepend(types, type);

    return types;
}

/* Make conn and data to point each to another. Does TrillianConnectionData needs it?
 What if PurpleConnection pointer gets changed? */
void trillian_connection_new(PurpleConnection *conn)
{
    g_assert(purple_connection_get_protocol_data(conn) == NULL);
    TrillianConnectionData *data = g_new0(TrillianConnectionData, 1);
    data->conn = conn;
    purple_connection_set_protocol_data(conn, data);
}

// returns -1 on error (keeps errno set), 0 on timeout, and 1 when amount of bytes
// received. Note, there's: no way to know a number of received bytes upon
// timeout. It can be introduced, but for now it's okay.
int try_recv(short fd, uint8_t* buf, int amount, int msec) {
    struct pollfd pfd = {fd: fd, events: POLLIN | POLLPRI};
    int ret = poll(&pfd, 1, msec);
    if (ret <= 0)
        return ret;
    ret = recv(fd, (char*)buf, amount, MSG_NOSIGNAL);
    return (ret < 0)? ret
        : (ret == amount)? 1
        : try_recv(fd, buf, amount - ret, msec);
}

void trillian_request_version(int fd) {
    send(fd, &version_request, sizeof(version_request), MSG_NOSIGNAL);
    uint8_t buf[sizeof(version_request)];
    switch(try_recv(fd, buf, sizeof(buf), 30000)) {
        case -1:
            purple_debug_info("trillian", strerror(errno));
            // todo: tell pidgin we quitting
            return;
        case 0:
            purple_debug_info("trillian", "version_request timed out\n");
            // todo: tell pidgin we quitting
            return;
        default:
            break;
    }
    if (memcmp(&version_request, (char*)buf, sizeof(version_request))) {
        const std::string err = "wrn: version_request reply differs, content:\n"
            + show_tlv_packet(buf, sizeof(buf)) + "\n";
        purple_debug_info("trillian", err.c_str());
    }
}

void trillian_comm_feature_set(int fd) {
    uint block_sz = sizeof(tlv_unit) + sizeof(tlv_unit16) + sizeof(STREAM::FEATURE_TLS);
    tlv_packet_data packet = { {magic: magic, channel: tlv_packet_header::tlv},
                                flags: tlv_packet_data::request, family: tlv_packet_data::stream,
                                msg_type: STREAM::FEATURES_SET, sequence: 0,
                                block_sz: block_sz };
    uint16bg_t type = { type: STREAM::FEATURES }, val_sz = sizeof(STREAM::FEATURE_TLS);
    uint16bg_t s = {STREAM::FEATURE_TLS};
    std::vector<uint8_t> dat = new_packet(&packet, type, val_sz, (uint8_t*)&s);
    send(fd, dat.data(), dat.size(), MSG_NOSIGNAL);
    uint8_t buf[dat.size()];
    switch(try_recv(fd, buf, sizeof(buf), 30000)) {
        case -1:
            purple_debug_info("trillian", strerror(errno));
            // todo: tell pidgin we quitting
            return;
        case 0:
            purple_debug_info("trillian", "feature_set timed out\n");
            // todo: tell pidgin we quitting
            return;
        default:
            break;
    }
    std::pair<uint8_t*, uint> val = tlv_nth_val(buf, sizeof(buf), 0);
    if (!val.first || val.second != sizeof(STREAM::FEATURE_TLS)) {
        purple_debug_info("trillian", "feature_set malformed reply\n");
        return; //todo pidgin we quitting
    }
    if (((uint16bg_t*)val.first)->get() != STREAM::FEATURE_TLS) {
        const std::string err = "wrn: feature_set unexpected value: "
            + to_hex(val.first, val.second) + "\n";
        purple_debug_info("trillian", err.c_str());
    }
}

void trillian_tcp_established_hook(gpointer data, gint src, const gchar *error_message) {
    std::string msg = "tcp connection";
    if (error_message) {
        msg += error_message;
        purple_debug_info("trillian", (msg + "\n").c_str());
        return;
    }
    ((TrillianConnectionData*)data)->trillian_tcp = src;
    purple_debug_info("trillian", (msg + "\n").c_str());
    // Negotiate an IMPP protocol version
    trillian_request_version(src);
    trillian_comm_feature_set(src);
}

void save_debug_port_hook(int listenfd, gpointer data) {
    std::string msg = "save_debug_port_hook";
    if (listenfd != -1)
        msg += " debug port wasn't opened"; // maybe perror would work?
    else
        ((TrillianConnectionData*)data)->debug_tcp = listenfd;
    msg += "\n";
    purple_debug_info("trillian", msg.c_str());
}

void trillian_connection_start_login(PurpleConnection *conn)
{
    PurpleAccount *acct = conn->account;
    TrillianConnectionData *data = (TrillianConnectionData*)purple_connection_get_protocol_data(conn);
    // const gchar *homeserver = purple_account_get_string(conn->account,
    //         PRPL_ACCOUNT_OPT_HOME_SERVER, DEFAULT_HOME_HOST);
    // data->homeserver = homeserver;
    // purple_connection_set_state(conn, PURPLE_CONNECTING); dunno what these do
    // purple_connection_update_progress(conn, "Logging in", 0, 3);
    // matrix_api_password_login(data, acct->username,
    //         purple_account_get_password(acct),
    //         purple_account_get_string(acct, "device_id", NULL),
    //         _login_completed, data);
    if (!purple_proxy_connect(0, acct, TEST_TRILLIAN_HOST,
                              TEST_TRILLIAN_PORT, trillian_tcp_established_hook, data)) {
        purple_debug_info("trillian", "purple_proxy_connect error\n");
        return; //todo: perror? and disabling the account
    }
    // purple_network_listen(DEBUG_PORT, SOCK_STREAM, save_debug_port_hook, data);
}

/**
 * Start the connection to a trillian account
 */
void trillian_login(PurpleAccount *acc)
{
    purple_debug_info("trillian", "trillian login\n");
    PurpleConnection *conn = purple_account_get_connection(acc);
    trillian_connection_new(conn);
    trillian_connection_start_login(conn);

    // purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing",
    //     acct, PURPLE_CALLBACK(trillianprpl_conv_send_typing), conn);

    // conn->flags |= PURPLE_CONNECTION_HTML;
}

// void trillian_connection_new(PurpleConnection *pc)
// {
//      TrillianConnectionData *conn;

//      g_assert(purple_connection_get_protocol_data(pc) == NULL);
//      conn = g_new0(TrillianConnectionData, 1);
//      conn->pc = pc;
//      purple_connection_set_protocol_data(pc, conn);
// }

static PurplePluginProtocolInfo prpl_info =
{
    OPT_PROTO_IM_IMAGE, // | OPT_PROTO_CHAT_TOPIC | OPT_PROTO_UNIQUE_CHATNAME,
    0,               /* user_splits, initialized in trillian_init() */
    0,               /* protocol_options, initialized in trillian_init() */
    {   /* icon_spec, a PurpleBuddyIconSpec */
        Formats,                   /* format */
        0,                               /* min_width */
        0,                               /* min_height */
        128,                             /* max_width */
        128,                             /* max_height */
        10000,                           /* max_filesize */
        PURPLE_ICON_SCALE_DISPLAY,       /* scale_rules */
    },
    trillian_list_icon,                  /* list_icon */
    0,                                  /* list_emblem */
    0,                                  /* status_text */
    0,                                  /* tooltip_text */
    trillian_status_types,               /* status_types */
    0,                                  /* blist_node_menu */
    0, //trillian_chat_info,                  /* chat_info */
    0, //trillian_chat_info_defaults,         /* chat_info_defaults */
    trillian_login,                      /* login */
    trillian_close,                      /* close */
    0,                                  /* send_im */
    0,                                  /* set_info */
    0,                                  /* send_typing */
    0,                                  /* get_info */
    0,                                  /* set_status */
    0,                                  /* set_idle */
    0,                                  /* change_passwd */
    0,                                  /* add_buddy */
    0,                                  /* add_buddies */
    0,                                  /* remove_buddy */
    0,                                  /* remove_buddies */
    0,                                  /* add_permit */
    0,                                  /* add_deny */
    0,                                  /* rem_permit */
    0,                                  /* rem_deny */
    0,                                  /* set_permit_deny */
    0, //trillian_join_chat,                  /* join_chat */
    0, //trillian_reject_chat,                /* reject_chat */
    0, //trillian_get_chat_name,              /* get_chat_name */
    0, //trillian_chat_invite,                /* chat_invite */
    0, //trillian_chat_leave,                 /* chat_leave */
    0,                                  /* chat_whisper */
    0, //trillian_chat_send,                  /* chat_send */
    0,                                  /* keepalive */
    0,                                  /* register_user */
    0,                                  /* get_cb_info */
    0,                                  /* get_cb_away */
    0,                                  /* alias_buddy */
    0,                                  /* group_buddy */
    0,                                  /* rename_group */
    0,                                  /* buddy_free */
    0,                                  /* convo_closed */
    0,                                  /* normalize */
    0,                                  /* set_buddy_icon */
    0,                                  /* remove_group */
    0, //trillian_get_cb_real_name,           /* get_cb_real_name */
    0,                                  /* set_chat_topic */
    0,                                  /* find_blist_chat */
    0,                                  /* roomlist_get_list */
    0,                                  /* roomlist_cancel */
    0,                                  /* roomlist_expand_category */
    0,                                  /* can_receive_file */
    0,                                  /* send_file */
    0,                                  /* new_xfer */
    0,                                  /* offline_message */
    0,                                  /* whiteboard_prpl_ops */
    0,                                  /* send_raw */
    0,                                  /* roomlist_room_serialize */
    0,                                  /* unregister_user */
    0,                                  /* send_attention */
    0,                                  /* get_attention_types */
    sizeof(PurplePluginProtocolInfo),      /* struct_size */
    0,                                  /* get_account_text_table */
    0,                                  /* initiate_media */
    0,                                  /* get_media_caps */
    0,                                  /* get_moods */
    0,                                  /* set_public_alias */
    0,                                  /* get_public_alias */
    0,                                  /* add_buddy_with_invite */
    0                                   /* add_buddies_with_invite */
};

// struct PurplePluginInfo requires these declarations not to be const
#define DEBUGSUFFIX "6trillian"
char PRPL_ID[]         = "prpl-" DEBUGSUFFIX;
char PLUGIN_NAME[]     = DEBUGSUFFIX;
char DISPLAY_VERSION[] = "1.0";
char SUMMARY[]         = "Trillian Protocol Plugin";
char DESCRIPTION[]     = "Trillian Protocol Plugin";
char AUTHOR[]          = "Konstantin Kharlamov <hi-angel@yandex.ru>";
char HOMEPAGE[]        = "https://www.trillian.im/";

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
    trillian_destroy, /* destroy */
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
    purple_debug_info("trillian", "starting up\n");
}

PURPLE_INIT_PLUGIN(¯\_(ツ)_/¯, init_plugin, info);

} // extern "C"
