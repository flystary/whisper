#include <libiptc/libiptc.h>
#include <linux/netfilter/x_tables.h>
#include <cstring>
#include <unistd.h>

#include "sampling.h"
#include "config.h"
#include "utility.h"

int tcp_recv_socket = -1;

const int TCP_HEADER_LENGTH = sizeof(tcphdr);

const int TCP_PACKET_LENGTH = TCP_HEADER_LENGTH + PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH;

const uint8_t FLAG_FIN = 0x01;
const uint8_t FLAG_SYN = 0x02;
const uint8_t FLAG_RST = 0x04;
const uint8_t FLAG_PSH = 0x08;
const uint8_t FLAG_ACK = 0x10;
const uint8_t FLAG_URG = 0x20;

enum UNPACK_RET {
    NOT_MATCH = 0,
    NO_PAYLOAD,
    X7_PAYLOAD,
    INVALID_PAYLOAD
};

void init_iptables_rule(PeerConfig *peerConfig);

void tcp_read_work(uv_work_t *tcp_read_work_req);

void tcp_timer_task(uv_timer_t *tcp_timer);

void tcp_send(PeerConfig *peerConfig);

void tcp_pack(PeerConfig *peerConfig, uint8_t flag, uint32_t seq, uint32_t ack_seq, char *tcp_packet, uint32_t tcp_packet_seq);

int tcp_unpack(
        char *buf,
        int len,
        int &iphdr_len,
        string &src_ip,
        int &tcphdr_len,
        uint16_t &src_port,
        uint8_t &flag,
        uint32_t &seq,
        uint32_t &ack,
        uint32_t &tcp_packet_seq,
        uint16_t &tcp_packet_id
);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void init_tcp(uv_loop_t *main_loop) {
    if (open_tcp) {
        tcp_recv_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
        if (tcp_recv_socket == -1) {
            logger->error("tcp socket creation failed");
            exit(TCP_RAW_SOCKET_ERROR);
        }

        for (auto &it: peerConfigMap) {
            auto *peerConfig = it.second;
            if (peerConfig->tcp) {
                peerConfig->tcp_dst.sin_family = AF_INET;
                peerConfig->tcp_dst.sin_port = htons(peerConfig->tcp_port);
                if (inet_pton(AF_INET, peerConfig->dst_host.data(), &peerConfig->tcp_dst.sin_addr) != 1) {
                    logger->error("tcp destination IP %s configuration failed");
                    exit(DST_ADDR_CONFIG_ERROR);
                }

                peerConfig->tcp_send_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
                if (peerConfig->tcp_send_socket == -1) {
                    logger->error("tcp socket creation failed");
                    exit(TCP_RAW_SOCKET_ERROR);
                }

                bind(peerConfig->tcp_send_socket, (sockaddr *) &peerConfig->src, sizeof(sockaddr));

                init_iptables_rule(peerConfig);

                init_peer_quality(&peerConfig->tcp_quality);
                peerConfig->tcp_last_time = get_current_msec();

                uv_mutex_init(&peerConfig->tcp_uv_mutex);

                uv_timer_init(main_loop, &peerConfig->tcp_uv_timer);
                peerConfig->tcp_uv_timer.data = peerConfig;
                uv_timer_start(
                        &peerConfig->tcp_uv_timer,
                        tcp_timer_task,
                        rand() % peerConfig->interval,
                        peerConfig->interval
                );
            }
        }

        auto *tcp_uv_work = new uv_work_t;
        uv_queue_work(main_loop, tcp_uv_work, tcp_read_work, nullptr);
    }
}

void tcp_read_work(uv_work_t *tcp_read_work_req) {
    fd_set read_fd;
    char recv_buf[1500];

    while (true) {
        memset(recv_buf, 0, sizeof(recv_buf));
        FD_ZERO(&read_fd);
        FD_SET(tcp_recv_socket, &read_fd);

        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = 1;

        int ret = select(tcp_recv_socket + 1, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                logger->error("fail to select tcp socket!");
                break;
            case 0:
                break;
            default: {
                ssize_t size = 0;
                do {
                    uint32_t addr_len = 0;
                    size = recv(tcp_recv_socket, recv_buf, sizeof(recv_buf), 0);
                    if (size > 0) {
                        // 对接收的包进行解封
                        uint32_t packet_seq = 0;
                        uint16_t packet_id = 0;

                        int iphdr_len = 0;
                        string src_ip;
                        uint16_t src_port;

                        int tcphdr_len = 0;
                        uint8_t tcp_flag = 0;
                        uint32_t tcp_seq = 0;
                        uint32_t tcp_ack = 0;

                        int unpack_ret = tcp_unpack(recv_buf, size, iphdr_len, src_ip, tcphdr_len, src_port, tcp_flag, tcp_seq, tcp_ack, packet_seq, packet_id);
                        if (unpack_ret == NOT_MATCH) {
                            continue;
                        }

                        auto it = peerConfigMap.find(src_ip + ":" + to_string(packet_id));
                        if (it == peerConfigMap.end()) {
                            continue;
                        }
                        auto *peerConfig = it->second;

                        if (peerConfig->dst_host != src_ip || peerConfig->tcp_port != src_port) {
                            continue;
                        }

                        uv_mutex_lock(&peerConfig->tcp_uv_mutex);

                        if (tcp_flag == (FLAG_SYN | FLAG_ACK) && peerConfig->tcp_status == TCP_SYN_SENT) {
                            peerConfig->tcp_status = TCP_ESTABLISHED;

                            peerConfig->tcp_next_seq = tcp_ack;
                            peerConfig->tcp_next_ack = tcp_seq + 1;

                        } else if ((tcp_flag & FLAG_FIN) > 0) {
                            uint32_t send_ack = size - iphdr_len - tcphdr_len;
                            send_ack = (send_ack == 0 ? 1 : send_ack) + tcp_seq;

                            char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
                            tcp_pack(
                                    peerConfig,
                                    FLAG_ACK,
                                    tcp_ack,
                                    send_ack,
                                    tcp_packet,
                                    0
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(peerConfig->tcp_send_socket, tcp_packet, TCP_HEADER_LENGTH, 0, (struct sockaddr *) &peerConfig->tcp_dst, sizeof(struct sockaddr));
                                if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", peerConfig->dst_host.data());
                            }

                            peerConfig->tcp_status = 0;
                        } else if ((tcp_flag & FLAG_RST) > 0) {
                            if (peerConfig->tcp_status == TCP_SYN_SENT) {
                                peerConfig->tcp_status = TCP_CLOSE;
                            } else {
                                peerConfig->tcp_status = 0;
                            }
                        } else if ((tcp_flag & FLAG_PSH) > 0 && unpack_ret == X7_PAYLOAD) {
                            record_peer_quality("tcp", peerConfig, src_ip, packet_id, packet_seq % 256);

                            peerConfig->tcp_next_seq = tcp_ack;
                            peerConfig->tcp_next_ack = tcp_seq + size - iphdr_len - tcphdr_len;

                        } else if ((tcp_flag & FLAG_PSH) > 0 && unpack_ret == INVALID_PAYLOAD) {
                            uint32_t send_ack = size - iphdr_len - tcphdr_len;
                            send_ack = (send_ack == 0 ? 1 : send_ack) + tcp_seq;

                            char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
                            tcp_pack(
                                    peerConfig,
                                    FLAG_ACK | FLAG_FIN,
                                    tcp_ack,
                                    send_ack,
                                    tcp_packet,
                                    0
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(peerConfig->tcp_send_socket, tcp_packet, TCP_HEADER_LENGTH, 0, (struct sockaddr *) &peerConfig->tcp_dst, sizeof(struct sockaddr));
                                    if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", peerConfig->dst_host.data());
                            }

                            peerConfig->tcp_status = 0;
                        }

                        uv_mutex_unlock(&peerConfig->tcp_uv_mutex);
                    }
                } while (size > 0);
                break;
            }
        }
    }
}

void tcp_timer_task(uv_timer_t *tcp_timer) {
    auto *peerConfig = (struct PeerConfig *) tcp_timer->data;

    //计算连通性、延迟和丢包
    cal_peer_quality(
            peerConfig,
            "tcp",
            &peerConfig->tcp_quality
    );

    tcp_send(peerConfig);
}

void tcp_send(PeerConfig *peerConfig) {
    auto *peer_quality = &peerConfig->tcp_quality;

    //发送TCP SYN
    uv_mutex_lock(&peerConfig->tcp_uv_mutex);

    uint64_t current_msec = get_current_msec();
    if (peerConfig->tcp_status == TCP_SYN_SENT && current_msec - peerConfig->tcp_last_time > peerConfig->timeout) {
        peerConfig->tcp_status = TCP_CLOSE;
        peerConfig->tcp_last_time = current_msec;
    }

    if (peerConfig->tcp_status == TCP_CLOSE) {
        uint32_t init_seq = rand() % 4294967295;

        //封装tcp包
        char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
        tcp_pack(
                peerConfig,
                FLAG_SYN,
                init_seq,
                0,
                tcp_packet,
                0
        );

        ssize_t send_ret = 0;
        for (int i = 0; i < 3; i++) {
            send_ret = sendto(peerConfig->tcp_send_socket, tcp_packet, TCP_HEADER_LENGTH, 0, (struct sockaddr *) &peerConfig->tcp_dst, sizeof(struct sockaddr));
            if (send_ret < 0) {
                usleep(5);
            } else {
                break;
            }
        }
        if (send_ret < 0) {
            logger->error("Peer Src: %s Peer Host: %s send tcp packet fail!",peerConfig->src_ip.data(), peerConfig->dst_host.data());
        }

        peerConfig->tcp_status = TCP_SYN_SENT;
    } else if (peerConfig->tcp_status == TCP_ESTABLISHED) {
        uv_mutex_lock(&peer_quality->uv_mutex);

        peer_quality->sampling_tab[peer_quality->sampling_index].send_time = get_current_msec();
        peer_quality->sampling_tab[peer_quality->sampling_index].recv_time = 0;
        peer_quality->sampling_tab[peer_quality->sampling_index].latency = -1;

        //封装tcp包
        char tcp_packet[TCP_PACKET_LENGTH] = {'\0'};
        tcp_pack(
                peerConfig,
                FLAG_PSH | FLAG_ACK,
                peerConfig->tcp_next_seq,
                peerConfig->tcp_next_ack,
                tcp_packet,
                peer_quality->sampling_index
        );

        peer_quality->sampling_index++;

        uv_mutex_unlock(&peer_quality->uv_mutex);

        ssize_t send_ret = 0;
        for (int i = 0; i < 3; i++) {
            send_ret = sendto(peerConfig->tcp_send_socket, tcp_packet, TCP_PACKET_LENGTH, 0, (struct sockaddr *) &peerConfig->tcp_dst, sizeof(struct sockaddr));
            if (send_ret < 0) {
                usleep(5);
            } else {
                break;
            }
        }
        if (send_ret < 0) {
            logger->error("Peer Host %s send tcp packet fail!", peerConfig->dst_host.data());
        }
    }

    uv_mutex_unlock(&peerConfig->tcp_uv_mutex);
}

void tcp_pack(PeerConfig *peerConfig, uint8_t flag, uint32_t seq, uint32_t ack_seq, char *tcp_packet, uint32_t tcp_packet_seq) {
    struct tcphdr *tcp_header = (struct tcphdr *) tcp_packet;

    // TCP header configuration
    tcp_header->source = peerConfig->src.sin_port;
    tcp_header->dest = peerConfig->tcp_dst.sin_port;
    tcp_header->seq = htonl(seq);
    tcp_header->ack_seq = htonl(ack_seq);
    tcp_header->doff = 5; // tcp header size
    tcp_header->fin = (flag & FLAG_FIN) > 0 ? 1 : 0;
    tcp_header->syn = (flag & FLAG_SYN) > 0 ? 1 : 0;
    tcp_header->rst = (flag & FLAG_RST) > 0 ? 1 : 0;
    tcp_header->psh = (flag & FLAG_PSH) > 0 ? 1 : 0;
    tcp_header->ack = (flag & FLAG_ACK) > 0 ? 1 : 0;
    tcp_header->urg = (flag & FLAG_URG) > 0 ? 1 : 0;

    if ((flag & FLAG_RST) > 0) {
        tcp_header->window = htons(0); // window size
    } else {
        tcp_header->window = htons(5840); // window size
    }
    tcp_header->urg_ptr = 0;

    if ((flag & FLAG_PSH) > 0) {
        char *tcp_payload = tcp_packet + TCP_HEADER_LENGTH;
        memcpy(tcp_payload, MAGIC_WORD, 2);
        uint16_to_bytes(PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH, tcp_payload + PAYLOAD_LENGTH_INDEX);
        tcp_payload[PAYLOAD_TYPE_INDEX] = PAYLOAD_TYPE_ECHO;
        uint16_to_bytes(peerConfig->flow_id, tcp_payload + PAYLOAD_ID_INDEX);
        uint32_to_bytes(tcp_packet_seq, tcp_payload + PAYLOAD_SEQ_INDEX);
        uint32_to_bytes(
                peerConfig->tcp_quality.avg_latency > 0 ? peerConfig->tcp_quality.avg_latency : 0,
                tcp_payload + PAYLOAD_LATENCY_INDEX
        );
        uint32_to_bytes(
                peerConfig->tcp_quality.jitter > 0 ? peerConfig->tcp_quality.jitter : 0,
                tcp_payload + PAYLOAD_JITTER_INDEX
        );
        uint32_to_bytes(
                peerConfig->tcp_quality.loss_rate > 0 ? peerConfig->tcp_quality.loss_rate : 0,
                tcp_payload + PAYLOAD_LOSS_RATE_INDEX
        );
        memcpy(tcp_payload + PAYLOAD_IDENTITY_INDEX, identity.data(), identity.length());
        generate_random_str(tcp_payload + PAYLOAD_RANDOM_STR_INDEX, PAYLOAD_RANDOM_STR_LENGTH);

        int psize = PSEUDO_HEADER_LENGTH + TCP_PACKET_LENGTH;
        char pseudogram[psize];
        auto *psh = (pseudo_header *) pseudogram;
        psh->source_address = peerConfig->src.sin_addr.s_addr;
        psh->dest_address = peerConfig->tcp_dst.sin_addr.s_addr;
        psh->placeholder = 0;
        psh->protocol = IPPROTO_TCP;
        psh->length = htons(TCP_PACKET_LENGTH);
        memcpy(pseudogram + PSEUDO_HEADER_LENGTH, tcp_packet, TCP_PACKET_LENGTH);

        tcp_header->check = checksum(pseudogram, psize);
    } else {
        int psize = PSEUDO_HEADER_LENGTH + TCP_HEADER_LENGTH;
        char pseudogram[psize];
        auto *psh = (pseudo_header *) pseudogram;
        psh->source_address = peerConfig->src.sin_addr.s_addr;
        psh->dest_address = peerConfig->tcp_dst.sin_addr.s_addr;
        psh->placeholder = 0;
        psh->protocol = IPPROTO_TCP;
        psh->length = htons(TCP_HEADER_LENGTH);
        memcpy(pseudogram + PSEUDO_HEADER_LENGTH, tcp_packet, TCP_HEADER_LENGTH);

        tcp_header->check = checksum(pseudogram, psize);
    }

}

int tcp_unpack(
        char *buf,
        int len,
        int &iphdr_len,
        string &src_ip,
        int &tcphdr_len,
        uint16_t &src_port,
        uint8_t &flag,
        uint32_t &seq,
        uint32_t &ack,
        uint32_t &tcp_packet_seq,
        uint16_t &tcp_packet_id
) {
    auto *ip_hdr = (struct ip *) buf;
    iphdr_len = ip_hdr->ip_hl * 4;

    len -= iphdr_len;

    if (len == 0) {
        return NOT_MATCH;
    }

    src_ip.assign(inet_ntoa(ip_hdr->ip_src));

    //使指针跳过IP头指向TCP头
    auto *tcp_header = (struct tcphdr *) (buf + iphdr_len);
    tcphdr_len = tcp_header->doff * 4;

    len -= tcphdr_len;

    src_port = ntohs(tcp_header->source);

    flag = buf[iphdr_len + 13];
    seq = ntohl(tcp_header->seq);
    ack = ntohl(tcp_header->ack_seq);

    if (tcp_header->psh == 1) {
        auto *tcp_payload = buf + iphdr_len + tcphdr_len;

        if (len != PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH
            || memcmp(tcp_payload, MAGIC_WORD, 2) != 0
            || bytes_to_uint16(tcp_payload + PAYLOAD_LENGTH_INDEX) != len
            || tcp_payload[PAYLOAD_TYPE_INDEX] != PAYLOAD_TYPE_ECHO_REPLY
                ) {
            return INVALID_PAYLOAD;
        }

        tcp_packet_id = bytes_to_uint16(tcp_payload + PAYLOAD_ID_INDEX);
        tcp_packet_seq = bytes_to_uint32(tcp_payload + PAYLOAD_SEQ_INDEX);

        return X7_PAYLOAD;
    } else {
        return NO_PAYLOAD;
    }
}

void init_iptables_rule(PeerConfig *peerConfig) {
    uint32_t size1 = XT_ALIGN(sizeof(struct ipt_entry));
    uint32_t size2 = XT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_tcp));
    uint32_t size3 = XT_ALIGN(sizeof(struct ipt_standard_target));

    struct ipt_entry *iptables_entry = nullptr;
    struct ipt_entry_match *iptables_entry_match = nullptr;
    struct ipt_tcp *iptables_tcp = nullptr;
    struct ipt_standard_target *iptables_entry_target = nullptr;

    iptables_entry = (ipt_entry *) calloc(1, size1 + size2 + size3);

    /* Offsets to the other bits */
    iptables_entry->target_offset = size1 + size2;
    iptables_entry->next_offset = size1 + size2 + size3;

    iptables_entry->ip.src.s_addr = INADDR_ANY;
    iptables_entry->ip.smsk.s_addr = 0;

    iptables_entry->ip.dst.s_addr = inet_addr(peerConfig->dst_host.data());
    iptables_entry->ip.dmsk.s_addr = inet_addr("255.255.255.255");

    iptables_entry->ip.proto = IPPROTO_TCP;
    iptables_entry->nfcache = 0x4000;  /*Think this stops caching. NFC_UNKNOWN*/

    /* TCP specific matching(ie. ports) */
    iptables_entry_match = (struct ipt_entry_match *) iptables_entry->elems;
    strcpy(iptables_entry_match->u.user.name, "tcp");
    iptables_entry_match->u.user.match_size = size2;

    iptables_tcp = (struct ipt_tcp *) iptables_entry_match->data;

    iptables_tcp->spts[0] = 0;
    iptables_tcp->spts[1] = 0xFFFF;

    iptables_tcp->dpts[0] = peerConfig->tcp_port;
    iptables_tcp->dpts[1] = peerConfig->tcp_port;

    iptables_tcp->flg_mask = FLAG_RST;
    iptables_tcp->flg_cmp = FLAG_RST;

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
