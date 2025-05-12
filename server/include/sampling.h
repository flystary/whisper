#ifndef WHISPER_SERVER_SAMPLING_H
#define WHISPER_SERVER_SAMPLING_H

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

#include <uv.h>
#include <map>
#include <string>

using std::string;
using std::map;

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

enum PACKET_TYPE {
    PAYLOAD_TYPE_ECHO = 1, PAYLOAD_TYPE_ECHO_REPLY
};

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t length;
};

struct Peer {
    string identity;
    string src_ip;
    uint16_t src_port;
    uint8_t protocol;

    uint32_t avg_latency;
    uint32_t jitter;
    uint32_t loss_rate;

    uint64_t last_time = 0;
};

extern uv_mutex_t peer_mutex;

extern map<string, Peer *> peer_map;

const int PSEUDO_HEADER_LENGTH = sizeof(pseudo_header);

void init_sampling(uv_loop_t *main_loop);

void init_udp(uv_loop_t *main_loop);

void init_tcp(uv_loop_t *main_loop);

unsigned short checksum(const char *buf, unsigned size);

void update_peer_info(
        const char *src_ip,
        uint8_t protocol,
        uint16_t packet_id,
        char *data
);

#endif //WHISPER_SERVER_SAMPLING_H
