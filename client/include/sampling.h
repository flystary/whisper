/*
0        7        15       23       31
+--------+--------+--------+--------+
|magic:7 |magic:x |  Length(uint16) |
|  type  |Reserved|    ID(uint16)   |
|            SEQ(uint32)            |
|        AVG Latency(uint32)        |
|           Jitter(uint32)          |
|         Loss Rate(uint32)         |
|              identity             |
|              identity             |
|              identity             |
|              identity             |
|              identity             |
|              identity             |
|              identity             |
|              identity             |
|            Rand String            |
|            Rand String            |
+--------+--------+--------+--------+
*/


#ifndef WHISPER_CLIENT_SAMPLING_H
#define WHISPER_CLIENT_SAMPLING_H

#include <string>

#include <uv.h>
#include <json/value.h>

using std::string;

const int PAYLOAD_LENGTH_INDEX = 2;
const int PAYLOAD_TYPE_INDEX = 4;
const int PAYLOAD_ID_INDEX = 6;
const int PAYLOAD_SEQ_INDEX = 8;
const int PAYLOAD_LATENCY_INDEX = 12;
const int PAYLOAD_JITTER_INDEX = 16;
const int PAYLOAD_LOSS_RATE_INDEX = 20;
const int PAYLOAD_IDENTITY_INDEX = 24;
const int PAYLOAD_RANDOM_STR_INDEX = 56;

const int PAYLOAD_RANDOM_STR_LENGTH = 8;

enum PAYLOAD_TYPE {
    PAYLOAD_TYPE_ECHO = 1, PAYLOAD_TYPE_ECHO_REPLY
};


struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t length;
};

const int PSEUDO_HEADER_LENGTH = sizeof(pseudo_header);

struct PeerSampling {
    uint64_t send_time = 0;
    uint64_t recv_time = 0;
    int16_t latency = -1;
};

struct PeerQuality {
    uv_mutex_t uv_mutex;

    int32_t avg_latency = -1;
    int32_t max_latency = -1;
    int32_t min_latency = -1;
    int32_t jitter = -1;
    int32_t loss_rate = -1;
    bool status;

    uint64_t last_time = 0;
    uint8_t sampling_index = 0;
    PeerSampling sampling_tab[256];
};

struct PeerConfig {
    string dst_host;
    string src_ip;
    sockaddr_in src;
    sockaddr_in udp_src;
    int timeout_num = 0;

    unsigned int interval;
    unsigned int timeout;
    unsigned int sampling_range;

    uint16_t flow_id;

    bool icmp;
    uv_timer_t icmp_uv_timer;
    sockaddr_in icmp_dst;
    uv_mutex_t icmp_uv_mutex;
    int icmp_send_socket = -1;
    int icmp_recv_socket = -1;
    int sock_raw = 0;
    int id_end = 0;
    int id_bg = 0;
    int id_index = 0;
    PeerQuality icmp_quality;

    bool tcp;
    unsigned int tcp_port;
    unsigned int tcp_mode;
    int tcp_status = TCP_CLOSE;
    uv_timer_t tcp_uv_timer;
    sockaddr_in tcp_dst;
    int tcp_send_socket = -1;
    PeerQuality tcp_quality;
    uv_mutex_t tcp_uv_mutex;
    uint64_t tcp_last_time = 0;
    uint32_t tcp_next_seq = 0;
    uint32_t tcp_next_ack = 0;


    bool udp;
    unsigned int udp_port;
    uv_timer_t udp_uv_timer;
    sockaddr_in udp_dst;
    int udp_send_socket = -1;
    PeerQuality udp_quality;
};

void init_icmp(uv_loop_t *main_loop);

void init_udp(uv_loop_t *main_loop);

void init_tcp(uv_loop_t *main_loop);

void init_peer_quality(PeerQuality *peer_quality);

void record_peer_quality(const string &protocol, struct PeerConfig *peerConfig, string &src_ip, uint16_t packet_id, uint8_t packet_index);

void cal_peer_quality(PeerConfig *peer_config, const string &protocol, PeerQuality *peer_quality);

void print_peer_quality(Json::Value &json_peer_quality, PeerQuality *peer_quality);

unsigned short checksum(const char *buf, unsigned size);

#endif //WHISPER_CLIENT_SAMPLING_H
