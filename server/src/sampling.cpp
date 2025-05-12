#include <map>

#include "sampling.h"
#include "utility.h"

using std::map;

uv_mutex_t peer_mutex;
uv_timer_t peer_timer;

map<string, Peer *> peer_map;

void peer_timer_task(uv_timer_t *http_poll_timer);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void init_sampling(uv_loop_t *main_loop) {
    uv_mutex_init(&peer_mutex);

    uv_timer_init(main_loop, &peer_timer);
    uv_timer_start(&peer_timer, peer_timer_task, 0, 60 * 1000);
}

void peer_timer_task(uv_timer_t *peer_timer) {
    uint64_t current_msec = get_current_msec();

    uv_mutex_lock(&peer_mutex);

    for (auto it = peer_map.begin(); it != peer_map.end();) {
        if (current_msec - it->second->last_time > 60 * 1000) {
            string protocol;
            if (it->second->protocol == IPPROTO_ICMP) {
                logger->info("%s:%s:%s:%d is timeout.",
                             it->second->identity.data(),
                             "icmp",
                             it->second->src_ip.data(),
                             it->second->src_port
                );
            } else if (it->second->protocol == IPPROTO_TCP) {
                logger->info("%s:%s:%s:%d is timeout.",
                             it->second->identity.data(),
                             "tcp",
                             it->second->src_ip.data(),
                             it->second->src_port
                );
            } else if (it->second->protocol == IPPROTO_UDP) {
                logger->info("%s:%s:%s:%d is timeout.",
                             it->second->identity.data(),
                             "udp",
                             it->second->src_ip.data(),
                             it->second->src_port
                );
            }
            delete it->second;
            peer_map.erase(it++);
        } else {
            it++;
        }
    }

    uv_mutex_unlock(&peer_mutex);
}

void update_peer_info(
        const char *src_ip,
        uint8_t protocol,
        uint16_t packet_id,
        char *data
) {
    string key;
    key.assign(src_ip);

    if (protocol == IPPROTO_ICMP) {
        key.append("-").append("icmp");
    } else if (protocol == IPPROTO_TCP) {
        key.append("-").append("tcp");
    } else if (protocol == IPPROTO_UDP) {
        key.append("-").append("udp");
    }
    key.append("-").append(std::to_string(packet_id));

    uv_mutex_lock(&peer_mutex);
    auto it = peer_map.find(key);

    Peer *peer;

    if (it == peer_map.end()) {
        peer = new Peer;
        peer->identity.assign(data + PAYLOAD_IDENTITY_INDEX);
        peer->src_ip.assign(src_ip);
        peer->protocol = protocol;
        peer->src_port = packet_id;

        peer_map.insert(map<string, Peer *>::value_type(key, peer));
    } else {
        peer = it->second;
    }

    peer->last_time = get_current_msec();

    peer->avg_latency = bytes_to_uint32(data + PAYLOAD_LATENCY_INDEX);
    peer->jitter = bytes_to_uint32(data + PAYLOAD_JITTER_INDEX);
    peer->loss_rate = bytes_to_uint32(data + PAYLOAD_LOSS_RATE_INDEX);

    uv_mutex_unlock(&peer_mutex);
}

unsigned short checksum(const char *buf, unsigned size) {
    unsigned sum = 0, i;

    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2) {
        unsigned short word16 = *(unsigned short *) &buf[i];
        sum += word16;
    }

    /* Handle odd-sized case */
    if (size & 1) {
        unsigned short word16 = (unsigned char) buf[i];
        sum += word16;
    }

    /* Fold to get the ones-complement result */
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    /* Invert to get the negative in ones-complement arithmetic */
    return ~sum;
}
