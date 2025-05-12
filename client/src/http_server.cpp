#include <string>
#include <json/json.h>

#include "http_server.h"
#include "config.h"
#include "sampling.h"
#include "utility.h"

extern "C" {
#include "mongoose.h"
}

using std::string;
using std::to_string;

static struct mg_mgr mgr;
static string s_http_address_port;
static char *ptr_server_root;
static struct mg_serve_http_opts s_http_server_opts;

uv_timer_t http_poll_timer;

void load_http_server_config();

void ev_handler(struct mg_connection *nc, int ev, void *ev_data);

void handle_peers(struct mg_connection *nc, struct http_message *hm);

void http_poll_timer_task(uv_timer_t *http_poll_timer);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void load_http_server_config() {
    s_http_address_port = "127.0.0.1:";
    s_http_address_port.append(to_string(http_port));

    char *pwd = get_current_dir_name();
    string server_root;
    server_root.assign(pwd);
    server_root.append("/wwwroot");

    ptr_server_root = new char[server_root.length() + 1];
    memset(ptr_server_root, '\0', server_root.length() + 1);
    strcpy(ptr_server_root, server_root.c_str());

    s_http_server_opts.document_root = ptr_server_root;

    free(pwd);
}

void init_http_server(uv_loop_t *loop) {
    struct mg_connection *nc;
    struct mg_bind_opts bind_opts;
    const char *err_str;

    mg_mgr_init(&mgr, nullptr);

    load_http_server_config();

    memset(&bind_opts, 0, sizeof(bind_opts));
    bind_opts.error_string = &err_str;
    nc = mg_bind_opt(&mgr, s_http_address_port.data(), ev_handler, bind_opts);
    if (nc == nullptr) {
        logger->error("Error starting HTTP server on %s :: *s", s_http_address_port.data(), bind_opts.error_string);
        exit(EXIT_FAILURE);
    }

    mg_set_protocol_http_websocket(nc);
    s_http_server_opts.enable_directory_listing = "no";

    logger->info("Starting HTTP server on %s , serving %s", s_http_address_port.data(), s_http_server_opts.document_root);

    uv_timer_init(loop, &http_poll_timer);
    uv_timer_start(&http_poll_timer, http_poll_timer_task, 0, 100);
}

void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    switch (ev) {
        case MG_EV_HTTP_REQUEST: {
            if (mg_vcmp(&hm->uri, "/api/peers") == 0) {
                handle_peers(nc, hm);
            }
        }

        default:
            break;
    }

}

void handle_peers(struct mg_connection *nc, struct http_message *hm) {
    if (strncmp("GET", hm->method.p, hm->method.len) != 0) {
        mg_printf(nc, "%s", "HTTP/1.1 405 Method Not Allowed\r\nTransfer-Encoding: chunked\r\n\r\n");
        mg_send_http_chunk(nc, "", 0);
    }

    Json::Value json_out;

    for (auto it = peerConfigMap.begin(); it != peerConfigMap.end();) {
        auto it_current = it;
        it++;

        auto *peer_config = it_current->second;


        Json::Value json_peer;
        json_peer["dst_host"] = peer_config->dst_host;
        json_peer["src_ip"] = peer_config->src_ip;

        if (peer_config->icmp) {
            Json::Value json_peer_icmp;
            print_peer_quality(json_peer_icmp, &peer_config->icmp_quality);
            json_peer["icmp"] = json_peer_icmp;
        }

        if (peer_config->udp) {
            Json::Value json_peer_udp;
            print_peer_quality(json_peer_udp, &peer_config->udp_quality);
            json_peer["udp"] = json_peer_udp;
        }

        if (peer_config->tcp) {
            Json::Value json_peer_tcp;
            print_peer_quality(json_peer_tcp, &peer_config->tcp_quality);
            json_peer["tcp"] = json_peer_tcp;
        }

        json_out.append(json_peer);
    }

    mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
    mg_printf_http_chunk(nc, json_out.toStyledString().data());
    mg_send_http_chunk(nc, "", 0);

}

void http_poll_timer_task(uv_timer_t *http_poll_timer) {
    mg_mgr_poll(&mgr, 1);
}
