#include <libiptc/libiptc.h>
#include <linux/netfilter/x_tables.h>
#include <cstring>
#include <unistd.h>

#include "sampling.h"
#include "config.h"
#include "utility.h"

const uint8_t FLAG_FIN = 0x01;
const uint8_t FLAG_SYN = 0x02;
const uint8_t FLAG_RST = 0x04;
const uint8_t FLAG_PSH = 0x08;
const uint8_t FLAG_ACK = 0x10;
const uint8_t FLAG_URG = 0x20;

enum UNPACK_RET {
    DST_PORT_NOT_MATCH = 0,
    NO_PAYLOAD,
    X7_PAYLOAD,
    INVALID_PAYLOAD
};

const int TCP_HEADER_LENGTH = sizeof(tcphdr);

const int TCP_PACKET_LENGTH = TCP_HEADER_LENGTH + PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH;

int tcp_socket = -1;
sockaddr_in sockaddr_src;

void init_iptables_rule();

void tcp_read_work(uv_work_t *tcp_read_work_req);

void tcp_pack(
        in_addr *src_addr,
        in_addr *dst_addr,
        uint16_t dst_port,
        uint8_t flag,
        uint32_t seq,
        uint32_t ack_seq,
        char *tcp_packet,
        uint32_t tcp_packet_seq,
        uint16_t tcp_packet_id
);

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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void init_tcp(uv_loop_t *main_loop) {
    tcp_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
    if (tcp_socket == -1) {
        logger->error("tcp socket creation failed");
        exit(TCP_RAW_SOCKET_ERROR);
    }

    sockaddr_src.sin_family = AF_INET;
    sockaddr_src.sin_port = htons(tcp_port);
    if (inet_pton(AF_INET, "0.0.0.0", &sockaddr_src.sin_addr) != 1) {
        printf("source IP configuration failed\n");
        exit(ADDR_CONFIG_ERROR);
    }

    bind(tcp_socket, (sockaddr *) &sockaddr_src, sizeof(sockaddr));

    init_iptables_rule();

    auto *tcp_uv_work = new uv_work_t;
    uv_queue_work(main_loop, tcp_uv_work, tcp_read_work, nullptr);
}

void tcp_read_work(uv_work_t *tcp_read_work_req) {
    fd_set read_fd;
    char recv_buf[128];
    while (true) {
        memset(recv_buf, 0, sizeof(recv_buf));
        FD_ZERO(&read_fd);
        FD_SET(tcp_socket, &read_fd);

        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = 1;

        int ret = select(tcp_socket + 1, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                logger->error("fail to select tcp socket!");
                break;
            case 0:
                break;
            default: {
                ssize_t size = 0;
                do {
                    sockaddr sockaddr_sender;
                    socklen_t socklen;
                    size = recv(tcp_socket, recv_buf, sizeof(recv_buf), 0);
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
                        if (unpack_ret == DST_PORT_NOT_MATCH) {
                            continue;
                        }

                        auto *ip_hdr = (struct ip *) recv_buf;

                        if (tcp_flag == FLAG_SYN) {
                            char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
                            tcp_pack(
                                    &ip_hdr->ip_dst,
                                    &ip_hdr->ip_src,
                                    src_port,
                                    FLAG_SYN | FLAG_ACK,
                                    rand() % 4294967295,
                                    tcp_seq + 1,
                                    tcp_packet,
                                    packet_seq,
                                    packet_id
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(tcp_socket, tcp_packet, TCP_HEADER_LENGTH, 0, &sockaddr_sender, socklen);
                                if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", src_ip.data());
                            }

                        } else if ((tcp_flag & FLAG_PSH) > 0 && unpack_ret == INVALID_PAYLOAD) {
                            char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
                            tcp_pack(
                                    &ip_hdr->ip_dst,
                                    &ip_hdr->ip_src,
                                    src_port,
                                    FLAG_FIN | FLAG_ACK,
                                    tcp_ack,
                                    tcp_seq + size - iphdr_len - tcphdr_len,
                                    tcp_packet,
                                    packet_seq,
                                    packet_id
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(tcp_socket, tcp_packet, TCP_HEADER_LENGTH, 0, &sockaddr_sender, socklen);
                                if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", src_ip.data());
                            }

                        } else if ((tcp_flag & FLAG_PSH) > 0 && unpack_ret == X7_PAYLOAD) {
                            update_peer_info(
                                    src_ip.data(),
                                    IPPROTO_TCP,
                                    packet_id,
                                    recv_buf + iphdr_len + tcphdr_len
                            );

                            char tcp_packet[TCP_PACKET_LENGTH] = {'\0'};
                            tcp_pack(
                                    &ip_hdr->ip_dst,
                                    &ip_hdr->ip_src,
                                    src_port,
                                    FLAG_PSH | FLAG_ACK,
                                    tcp_ack,
                                    tcp_seq + size - iphdr_len - tcphdr_len,
                                    tcp_packet,
                                    packet_seq,
                                    packet_id
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(tcp_socket, tcp_packet, TCP_PACKET_LENGTH, 0, &sockaddr_sender, socklen);
                                if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", src_ip.data());
                            }

                        } else if ((tcp_flag & FLAG_FIN) > 0) {
                            uint32_t send_ack = size - iphdr_len - tcphdr_len;
                            send_ack = (send_ack == 0 ? 1 : send_ack) + tcp_seq;
                            char tcp_packet[TCP_HEADER_LENGTH] = {'\0'};
                            tcp_pack(
                                    &ip_hdr->ip_dst,
                                    &ip_hdr->ip_src,
                                    src_port,
                                    FLAG_ACK,
                                    tcp_ack,
                                    send_ack,
                                    tcp_packet,
                                    packet_seq,
                                    packet_id
                            );

                            ssize_t send_ret = 0;
                            for (int i = 0; i < 3; i++) {
                                send_ret = sendto(tcp_socket, tcp_packet, TCP_HEADER_LENGTH, 0, &sockaddr_sender, socklen);
                                if (send_ret < 0) {
                                    usleep(5);
                                } else {
                                    break;
                                }
                            }
                            if (send_ret < 0) {
                                logger->error("Peer Host %s send tcp packet fail!", src_ip.data());
                            }

                        }
                    }
                } while (size > 0);
                break;
            }
        }
    }
}

void tcp_pack(
        in_addr *src_addr,
        in_addr *dst_addr,
        uint16_t dst_port,
        uint8_t flag,
        uint32_t seq,
        uint32_t ack_seq,
        char *tcp_packet,
        uint32_t tcp_packet_seq,
        uint16_t tcp_packet_id
) {
    struct tcphdr *tcp_header = (struct tcphdr *) tcp_packet;

    // TCP header configuration
    tcp_header->source = htons(tcp_port);
    tcp_header->dest = htons(dst_port);
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
        tcp_payload[PAYLOAD_TYPE_INDEX] = PAYLOAD_TYPE_ECHO_REPLY;
        uint16_to_bytes(tcp_packet_id, tcp_payload + PAYLOAD_ID_INDEX);
        uint32_to_bytes(tcp_packet_seq, tcp_payload + PAYLOAD_SEQ_INDEX);
        generate_random_str(tcp_payload + PAYLOAD_RANDOM_STR_INDEX, PAYLOAD_RANDOM_STR_LENGTH);

        int psize = PSEUDO_HEADER_LENGTH + TCP_PACKET_LENGTH;
        char pseudogram[psize];
        auto *psh = (pseudo_header *) pseudogram;
        psh->source_address = src_addr->s_addr;
        psh->dest_address = dst_addr->s_addr;
        psh->placeholder = 0;
        psh->protocol = IPPROTO_TCP;
        psh->length = htons(TCP_PACKET_LENGTH);
        memcpy(pseudogram + PSEUDO_HEADER_LENGTH, tcp_packet, TCP_PACKET_LENGTH);

        tcp_header->check = checksum(pseudogram, psize);
    } else {
        int psize = PSEUDO_HEADER_LENGTH + TCP_HEADER_LENGTH;
        char pseudogram[psize];
        auto *psh = (pseudo_header *) pseudogram;
        psh->source_address = src_addr->s_addr;
        psh->dest_address = dst_addr->s_addr;
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
        return DST_PORT_NOT_MATCH;
    }

    src_ip.assign(inet_ntoa(ip_hdr->ip_src));

    //使指针跳过IP头指向TCP头
    auto *tcp_header = (struct tcphdr *) (buf + iphdr_len);
    tcphdr_len = tcp_header->doff * 4;

    len -= tcphdr_len;

    src_port = ntohs(tcp_header->source);
    uint16_t dst_port = ntohs(tcp_header->dest);

    if (dst_port != tcp_port) {
        return DST_PORT_NOT_MATCH;
    }
    tcp_packet_id = src_port;

    flag = buf[iphdr_len + 13];
    seq = ntohl(tcp_header->seq);
    ack = ntohl(tcp_header->ack_seq);

    if (tcp_header->psh == 1) {
        auto *tcp_payload = buf + iphdr_len + tcphdr_len;

        if (len != PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH
            || memcmp(tcp_payload, MAGIC_WORD, 2) != 0
            || bytes_to_uint16(tcp_payload + PAYLOAD_LENGTH_INDEX) != len
            || tcp_payload[PAYLOAD_TYPE_INDEX] != PAYLOAD_TYPE_ECHO
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

void init_iptables_rule() {
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

    iptables_entry->ip.dst.s_addr = INADDR_ANY;
    iptables_entry->ip.dmsk.s_addr = 0;

    iptables_entry->ip.proto = IPPROTO_TCP;
    iptables_entry->nfcache = 0x4000;  /*Think this stops caching. NFC_UNKNOWN*/

    /* TCP specific matching(ie. ports) */
    iptables_entry_match = (struct ipt_entry_match *) iptables_entry->elems;
    strcpy(iptables_entry_match->u.user.name, "tcp");
    iptables_entry_match->u.user.match_size = size2;

    iptables_tcp = (struct ipt_tcp *) iptables_entry_match->data;

    iptables_tcp->dpts[0] = 0;
    iptables_tcp->dpts[1] = 0xFFFF;

    iptables_tcp->spts[0] = tcp_port;
    iptables_tcp->spts[1] = tcp_port;

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
