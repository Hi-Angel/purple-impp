//TODO BEFORE-UPSTREAMING:
// 1. clean up the structs
// 2. rename functions, variables — many of them have "default" names due to me trying to make a
// minimal working prototype
// 3. split the code
// 4. grep -rnIi matrix
// 5. server is hardcoded, I need to construct some "DNS SRV lookup", whatever it is.
// 6. rename trillian → impp in case somebody gonna write a purple web-wrapper.
// 7. mention in readme about the cereal const bug
// 8. worth putting some debug prints into both tlv_unit deserialization funcs.
// 9. whatever todos are in the code.
// 10. pidgin keeps crashing on disconnect. Judging by stacktrace I might be
// notifying it about broken connection wrong, e.g. maybe I don't clear something
// which leads to pidgin's attempts to access it… Have to ask somebody, probably.

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
#include "common-consts.h"

using namespace std;

extern "C" {

char Formats[] = "png,jpg,gif";
const char DEFAULT_HOME_HOST[] = "_tcp.trillian.im";
const char TEST_TRILLIAN_HOST[] = "74.201.34.42";
const uint TEST_TRILLIAN_PORT = 3158;
const char PRPL_ACCOUNT_OPT_HOME_SERVER[] = "home_server";
const uint min_pckt_sz = sizeof(tlv_packet_version);

struct ConnState {
    // scratch buf for input data. Performance-wise it supposed to leave allocated
    // space untouched most of times on shrink, hence just do resize() instead of
    // storing a uint for tracking the size.
    // todo: performance-wise std::dequeue is better, but unclear how to deal with
    // uncontiguous memory, nor a priority
    std::vector<uint8_t> buf;
};

struct TrillianConnectionData {
    PurpleConnection *conn;
    int trillian_tcp;
    const gchar *homeserver;      /* URL of the homeserver. Always ends in '/' */
    const gchar *user_id;         /* our full user id ("@user:server") */
    const gchar *access_token;    /* access token corresponding to our user */
    ConnState* state;
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
    free(data->state);
    // todo: tell pidgin it's over
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

/* Make conn and data to point each to another */
void trillian_connection_new(PurpleConnection *conn) {
    g_assert(purple_connection_get_protocol_data(conn) == NULL);
    TrillianConnectionData *data = g_new0(TrillianConnectionData, 1);
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

variant<int, tlv_packet_version, tlv_packet_data> recv_pckt(int fd, int msec) {
    uint8_t buf[tlv_packet_data::min_data_pckt_sz];
    int ret = try_recv(fd, buf, min_pckt_sz, msec);
    if (ret <= 0)
        return {ret};
    auto maybe_min_pckt = deserialize_pckt(buf, min_pckt_sz);
    if (holds_alternative<tlv_packet_version>(maybe_min_pckt))
        return {get<tlv_packet_version>(maybe_min_pckt)};
    ret = try_recv(fd, buf + min_pckt_sz, tlv_packet_data::min_data_pckt_sz - min_pckt_sz, msec);
    if (ret <= 0)
        return {ret};
    if (holds_alternative<std::string>(maybe_min_pckt)) {
        purple_debug_info("trillian", ("err:" + std::get<std::string>(maybe_min_pckt) + "\n").c_str());
        return {-1}; //unlikely to happen anyway
    }

    // receive the units
    tlv_packet_data& pckt = get<tlv_packet_data>(maybe_min_pckt);
    assert(pckt.block.size() == 0);
    pckt.block.resize(pckt.block_sz.get());
    pair<int,vector<tlv_unit>> p = recv_units(fd, pckt.block_sz.get(), msec);
    if (p.first <= 0)
        return {p.first};
    pckt.block += p.second;
    return {pckt};
}

const std::string trillian_request_version(int fd) {
    send(fd, &templ_version_request, sizeof(templ_version_request), MSG_NOSIGNAL);
    uint8_t buf[sizeof(templ_version_request)];
    switch(try_recv(fd, buf, sizeof(buf), 30000)) {
        case -1:
            // todo: tell pidgin we're quitting
            return strerror_newl(errno);
        case 0:
            // todo: tell pidgin we're quitting
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

std::string trillian_comm_feature_set(int fd) {
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
            // todo: tell pidgin we're quitting
            return strerror_newl(errno);
        case 0:
            // todo: tell pidgin we're quitting
            return "feature_set timed out\n";
        default:
            break;
    }
    auto reply = deserialize_pckt(buf, sizeof(buf));
    std::string err = (std::holds_alternative<std::string>(reply))? std::get<std::string>(reply)
        : (std::holds_alternative<tlv_packet_version>(reply))? "version instead of data"
        : (std::get<tlv_packet_data>(reply).block.size() != 1)? "unexpected number of units"
        : (std::get<tlv_packet_data>(reply).szval_at(0) != sizeof(uint16bg_t))? "unexpected amount of data"
        : "";
    if (!err.empty()) {
        //todo pidgin we're quitting
        return err + "\n";
    }
    if (std::get<tlv_packet_data>(reply).uint16_val_at(0) != STREAM::FEATURE_TLS) {
        return "wrn: feature_set unexpected value: "
            + std::to_string(std::get<tlv_packet_data>(reply).uint16_val_at(0)) + "\n";
    }
    return "";
}

static void data_incoming(gpointer in, PurpleSslConnection *ssl, PurpleInputCondition) {
    purple_debug_info("trillian", "data_incoming called\n");
    TrillianConnectionData* t_data = ((TrillianConnectionData*)in);
    std::vector<uint8_t>& buf = t_data->state->buf;
    do {
        uint old_sz = buf.size(), toread = 256;
        buf.resize(old_sz + toread);
        int bytes = purple_ssl_read(ssl, &buf[0], toread);
        if (bytes <= 0) {
            purple_debug_info("trillian", ("wrn: bytes recvd " + to_string(bytes) + "\n").c_str());
            if (errno == EAGAIN)
                return;
            else {
                // todo: this code makes pidgin to load 100% CPU, and then crash.
                string err = (errno == 0)? "Server closed connection"
                    : string{"Lost connection with "} + g_strerror(errno);
                auto reason = (t_data->conn->wants_to_die)? PURPLE_CONNECTION_ERROR_OTHER_ERROR
                    : PURPLE_CONNECTION_ERROR_NETWORK_ERROR;
                purple_connection_error_reason(t_data->conn, reason, err.c_str());
                return;
            }
        }
        if ((uint)bytes != toread) {
            fprintf(stderr, "bytes %d\n", bytes);
            buf.resize(old_sz + (uint)bytes);
            break;
        }
    } while (true);
    // if deserializeble, process and clear input vector
    variant<tlv_packet_data,tlv_packet_version,std::string> pckt = deserialize_pckt(buf.data(), buf.size());
    if (holds_alternative<string>(pckt)) {
        string err = "can't deserialize incoming pckt: " + get<string>(pckt) + "\n";
        purple_debug_info("trillian", err.c_str());
        return; //todo: assume for now not all data came
    } else if (holds_alternative<tlv_packet_version>(pckt)) {
        purple_debug_info("trillian", "wrn: version in the middle of a session\n");
        buf.erase(buf.begin(), buf.begin() + sizeof(tlv_packet_version));
    } else { // tlv_packet_data
        // todo
        purple_debug_info("trillian", (show_tlv_packet_data(get<tlv_packet_data>(pckt), 0) + "\n").c_str());
        buf.erase(buf.begin(), buf.begin() + get<tlv_packet_data>(pckt).curr_pckt_sz());
    }
}

void trillian_on_tls_connect(gpointer data, PurpleSslConnection *ssl, PurpleInputCondition) {
    purple_debug_info("trillian", "SSL connection established\n");
    TrillianConnectionData* t_data = ((TrillianConnectionData*)data);
    t_data->state = new ConnState;
    purple_ssl_input_add(ssl, data_incoming, t_data);

    const char* name = purple_account_get_username(t_data->conn->account);
    const char* pass = purple_account_get_password(t_data->conn->account);
    tlv_packet_data auth = templ_authorize;
    auth.block[1].set_val(vector<uint8_t>{name, name + strlen(name)});
    auth.block[2].set_val(vector<uint8_t>{pass, pass + strlen(pass)});
    const std::vector<uint8_t> dat_auth = serialize(auth);
    purple_ssl_write(ssl, dat_auth.data(), dat_auth.size());
    print_tlv_packet(dat_auth.data(), dat_auth.size());

    const std::vector<uint8_t> dat_info = serialize(templ_client_info);
    purple_ssl_write(ssl, dat_info.data(), dat_info.size());
    print_tlv_packet(dat_info.data(), dat_info.size());
    purple_debug_info("trillian", "sent!\n");
}

void trillian_tcp_established_hook(gpointer data, gint src, const gchar *error_message) {
    std::string ret ="tcp-connection";
    if (error_message) {
        ret += error_message;
        purple_debug_info("trillian", (ret + "\n").c_str());
        return;
    }
    TrillianConnectionData* con_dat = ((TrillianConnectionData*)data);
    con_dat->trillian_tcp = src;
    purple_debug_info("trillian", (ret + " is in progress\n").c_str());
    // Negotiate an IMPP protocol version
    ret = trillian_request_version(src);
    if (!ret.empty()) { // todo pidgin we're quitting
        purple_debug_info("trillian", ret.c_str());
        return;
    }
    ret = trillian_comm_feature_set(src);
    if (!ret.empty()) { // todo pidgin we're quitting
        purple_debug_info("trillian", ret.c_str());
        return;
    }
    purple_debug_info("trillian", "tcp-connection established, configuring TLS\n");
    auto ssl_err = [](PurpleSslConnection*, PurpleSslErrorType, gpointer) {
            purple_debug_info("trillian", "TLS error\n"); //todo
        };
    purple_ssl_connect_with_host_fd(con_dat->conn->account, src, trillian_on_tls_connect,
                                    ssl_err,
                                    TEST_TRILLIAN_HOST, data);
}

void trillian_connection_start_login(PurpleConnection *conn) {
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
#define DEBUGSUFFIX "9trillian"
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
    trillian_destroy,        /* destroy */
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
