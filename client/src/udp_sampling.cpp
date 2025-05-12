#include <unistd.h>
#include <cstring>
#include <netinet/udp.h>

#include <libiptc/libiptc.h>
#include <linux/netfilter/x_tables.h>

#include "sampling.h"
#include "config.h"
#include "utility.h"

int udp_recv_socket;

const int UDP_HEADER_LENGTH = sizeof(udphdr);

const int UDP_PACKET_LENGTH = UDP_HEADER_LENGTH + PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH;

void init_iptables_icmp_rule(PeerConfig *peerConfig);

void udp_read_work(uv_work_t *udp_read_work_req);

void udp_timer_task(uv_timer_t *udp_timer);

void udp_send(PeerConfig *peerConfig);

void udp_pack(PeerConfig *peerConfig, PeerQuality *peer_quality, char *udp_packet);

bool udp_unpack(char *buf, int len, uint32_t &udp_packet_seq, uint16_t &udp_packet_id, string &src_ip);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void init_udp(uv_loop_t *main_loop) {
    if (open_udp) {
        udp_recv_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
        if (udp_recv_socket == -1) {
            logger->error("udp socket creation failed");
            exit(UDP_RAW_SOCKET_ERROR);
        }

        for (auto &it: peerConfigMap) {
            auto *peerConfig = it.second;
            if (peerConfig->udp) {
                peerConfig->udp_dst.sin_family = AF_INET;
                peerConfig->udp_dst.sin_port = htons(peerConfig->udp_port);
                if (inet_pton(AF_INET, peerConfig->dst_host.data(), &peerConfig->udp_dst.sin_addr) != 1) {
                    logger->error("udp destination IP %s configuration failed");
                    exit(DST_ADDR_CONFIG_ERROR);
                }

                peerConfig->udp_send_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
                if (peerConfig->udp_send_socket == -1) {
                    logger->error("udp socket creation failed");
                    exit(UDP_RAW_SOCKET_ERROR);
                }

                bind(peerConfig->udp_send_socket, (sockaddr *) &peerConfig->udp_src, sizeof(sockaddr));

                init_iptables_icmp_rule(peerConfig);

                init_peer_quality(&peerConfig->udp_quality);

                uv_timer_init(main_loop, &peerConfig->udp_uv_timer);
                peerConfig->udp_uv_timer.data = peerConfig;
                uv_timer_start(
                        &peerConfig->udp_uv_timer,
                        udp_timer_task,
                        rand() % peerConfig->interval,
                        peerConfig->interval
                );
            }
        }

        auto *udp_uv_work = new uv_work_t;
        uv_queue_work(main_loop, udp_uv_work, udp_read_work, nullptr);
    }
}

void udp_read_work(uv_work_t *udp_read_work_req) {
    fd_set read_fd;
    char recv_buf[128];

    while (true) {
        memset(recv_buf, 0, sizeof(recv_buf));
        FD_ZERO(&read_fd);
        FD_SET(udp_recv_socket, &read_fd);

        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = 1;

        int ret = select(udp_recv_socket + 1, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                logger->error("fail to select udp socket!");
                break;
            case 0:
                break;
            default: {
                ssize_t size = 0;
                do {
                    uint32_t addr_len = 0;
                    size = recv(udp_recv_socket, recv_buf, sizeof(recv_buf), 0);
                    if (size > 0) {
                        // 对接收的包进行解封
                        uint32_t packet_seq = 0;
                        uint16_t packet_id = 0;
                        string src_ip;
                        if (!udp_unpack(recv_buf, size, packet_seq, packet_id, src_ip)) {
                            continue;
                        }

                        auto it = peerConfigMap.find(src_ip + ":" + to_string(packet_id));
                        if (it == peerConfigMap.end()) {
                            continue;
                        }

                        auto *peerConfig = it->second;

                        record_peer_quality("udp", peerConfig, src_ip, packet_id, packet_seq % 256);
                    }
                } while (size > 0);
                break;
            }
        }
    }
}

void udp_timer_task(uv_timer_t *udp_timer) {
    auto *peerConfig = (struct PeerConfig *) udp_timer->data;

    //计算连通性、延迟和丢包
    cal_peer_quality(
            peerConfig,
            "udp",
            &peerConfig->udp_quality
    );

    //发送UDP ECHO
    udp_send(peerConfig);
}

void udp_send(PeerConfig *peerConfig) {
    auto *peer_quality = &peerConfig->udp_quality;

    uv_mutex_lock(&peer_quality->uv_mutex);

    peer_quality->sampling_tab[peer_quality->sampling_index].send_time = get_current_msec();
    peer_quality->sampling_tab[peer_quality->sampling_index].recv_time = 0;
    peer_quality->sampling_tab[peer_quality->sampling_index].latency = -1;

    //封装udp包
    char udp_packet[UDP_PACKET_LENGTH] = {'\0'};
    udp_pack(
            peerConfig,
            peer_quality,
            udp_packet
    );

    peer_quality->sampling_index++;

    uv_mutex_unlock(&peer_quality->uv_mutex);

    ssize_t send_ret = 0;
    for (int i = 0; i < 3; i++) {
        send_ret = sendto(peerConfig->udp_send_socket, udp_packet, UDP_PACKET_LENGTH, 0, (struct sockaddr *) &peerConfig->udp_dst, sizeof(struct sockaddr));
        if (send_ret < 0) {
            usleep(5);
        } else {
            break;
        }
    }
    if (send_ret < 0) {
        logger->error("Peer Host %s send udp packet fail!", peerConfig->dst_host.data());
    }
}

void udp_pack(PeerConfig *peerConfig, PeerQuality *peer_quality, char *udp_packet) {
    struct udphdr *udp_header = (struct udphdr *) udp_packet;
    udp_header->source = peerConfig->udp_src.sin_port;
    udp_header->dest = peerConfig->udp_dst.sin_port;
    udp_header->len = htons(UDP_PACKET_LENGTH);

    char *udp_payload = udp_packet + UDP_HEADER_LENGTH;
    memcpy(udp_payload, MAGIC_WORD, 2);
    uint16_to_bytes(PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH, udp_payload + PAYLOAD_LENGTH_INDEX);
    udp_payload[PAYLOAD_TYPE_INDEX] = PAYLOAD_TYPE_ECHO;
    uint16_to_bytes(peerConfig->flow_id, udp_payload + PAYLOAD_ID_INDEX);
    uint32_to_bytes(peer_quality->sampling_index, udp_payload + PAYLOAD_SEQ_INDEX);
    uint32_to_bytes(
            peerConfig->udp_quality.avg_latency > 0 ? peerConfig->udp_quality.avg_latency : 0,
            udp_payload + PAYLOAD_LATENCY_INDEX
    );
    uint32_to_bytes(
            peerConfig->udp_quality.jitter > 0 ? peerConfig->udp_quality.jitter : 0,
            udp_payload + PAYLOAD_JITTER_INDEX
    );
    uint32_to_bytes(
            peerConfig->udp_quality.loss_rate > 0 ? peerConfig->udp_quality.loss_rate : 0,
            udp_payload + PAYLOAD_LOSS_RATE_INDEX
    );
    memcpy(udp_payload + PAYLOAD_IDENTITY_INDEX, identity.data(), identity.length());
    generate_random_str(udp_payload + PAYLOAD_RANDOM_STR_INDEX, PAYLOAD_RANDOM_STR_LENGTH);

    int psize = PSEUDO_HEADER_LENGTH + UDP_PACKET_LENGTH;
    char pseudogram[psize];
    auto *psh = (pseudo_header *) pseudogram;
    psh->source_address = peerConfig->src.sin_addr.s_addr;
    psh->dest_address = peerConfig->udp_dst.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_UDP;
    psh->length = htons(UDP_PACKET_LENGTH);
    memcpy(pseudogram + PSEUDO_HEADER_LENGTH, udp_packet, UDP_PACKET_LENGTH);

    udp_header->check = checksum(pseudogram, psize);
}

bool udp_unpack(char *buf, int len, uint32_t &udp_packet_seq, uint16_t &udp_packet_id, string &src_ip) {
    auto *ip_hdr = (struct ip *) buf;
    int iphdr_len = ip_hdr->ip_hl * 4;

    len -= iphdr_len;

    if (len == 0) {
        return false;
    }

    //使指针跳过IP头指向UDP头
    auto *udp_header = (struct udphdr *) (buf + iphdr_len);
    int udp_length = ntohs(udp_header->len);

    if (len != udp_length || udp_length != UDP_PACKET_LENGTH) {
        return false;
    }

    len -= UDP_HEADER_LENGTH;

    auto *udp_payload = buf + iphdr_len + UDP_HEADER_LENGTH;

    if (memcmp(udp_payload, MAGIC_WORD, 2) != 0
        || bytes_to_uint16(udp_payload + PAYLOAD_LENGTH_INDEX) != len
        || udp_payload[PAYLOAD_TYPE_INDEX] != PAYLOAD_TYPE_ECHO_REPLY
            ) {
        return false;
    }

    src_ip.assign(inet_ntoa(ip_hdr->ip_src));
    uint16_t dst_port = ntohs(udp_header->dest);

    udp_packet_id = bytes_to_uint16(udp_payload + PAYLOAD_ID_INDEX);
    udp_packet_seq = bytes_to_uint32(udp_payload + PAYLOAD_SEQ_INDEX);

    return true;
}

void init_iptables_icmp_rule(PeerConfig *peerConfig) {
    struct ipt_entry *iptables_entry = nullptr;
    struct ipt_entry_match *iptables_entry_match = nullptr;
    struct ipt_icmp *iptables_icmp = nullptr;
    struct ipt_standard_target *iptables_entry_target = nullptr;

    uint32_t size1 = XT_ALIGN(sizeof(struct ipt_entry));
    uint32_t size2 = XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_icmp));
    uint32_t size3 = XT_ALIGN(sizeof(struct ipt_standard_target));

    iptables_entry = (ipt_entry *) calloc(1, size1 + size2 + size3);

    /* Offsets to the other bits */
    iptables_entry->target_offset = size1 + size2;
    iptables_entry->next_offset = size1 + size2 + size3;

    iptables_entry->ip.src.s_addr = INADDR_ANY;
    iptables_entry->ip.smsk.s_addr = 0;

    iptables_entry->ip.dst.s_addr = inet_addr(peerConfig->dst_host.data());
    iptables_entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");

    iptables_entry->ip.proto = IPPROTO_ICMP;
    iptables_entry->nfcache = 0x4000;  /*Think this stops caching. NFC_UNKNOWN*/

    /* ICMP specific matching(ie. ports) */
    iptables_entry_match = (struct ipt_entry_match *) iptables_entry->elems;
    strcpy(iptables_entry_match->u.user.name, "icmp");
    iptables_entry_match->u.user.match_size = size2;

    iptables_icmp = (struct ipt_icmp *) iptables_entry_match->data;
    iptables_icmp->type = ICMP_UNREACH;
    iptables_icmp->code[0] = ICMP_UNREACH_PORT;
    iptables_icmp->code[1] = ICMP_UNREACH_PORT;

    iptables_entry_target = (struct ipt_standard_target *) (iptables_entry->elems + size2);
    iptables_entry_target->target.u.user.target_size = size3;
    strcpy(iptables_entry_target->target.u.user.name, "DROP");

    struct xtc_handle *p_handle = iptc_init("filter");

    auto *mask = (unsigned char *) malloc(size1 + size2 + size3);
    memset(mask, 0xff, size1 + size2 + size3);

    if (!iptc_check_entry("OUTPUT", iptables_entry, mask, p_handle)) {
        if (!iptc_append_entry("OUTPUT", iptables_entry, p_handle)) {
            logger->error("IPTABLES configuration failed");
            exit(IPTABLES_CONFIG_ERROR);
        }

        if (!iptc_commit(p_handle)) {
            logger->error("IPTABLES configuration failed");
            exit(IPTABLES_CONFIG_ERROR);
        }
    }

    free(iptables_entry);
    free(mask);
}
