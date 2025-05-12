#include "sampling.h"

#include <unistd.h>
#include <cstring>

#include "sampling.h"
#include "config.h"
#include "utility.h"

uv_udp_t udp_socket;

void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);

void udp_on_read(uv_udp_t *udp_socket_ptr, ssize_t packet_size, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);

void udp_send(uint16_t udp_packet_id, uint32_t udp_packet_seq, const struct sockaddr *dst_addr);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



void init_udp(uv_loop_t *main_loop) {
    struct sockaddr_in server_addr;
    uv_ip4_addr(listen_ip.c_str(), udp_port, &server_addr);

    if (uv_udp_init(main_loop, &udp_socket) < 0) {
        logger->error("udp socket creation failed");
        exit(UDP_UV_SOCKET_ERROR);
    }

    uv_udp_bind(&udp_socket, (const struct sockaddr *) &server_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&udp_socket, udp_alloc_cb, udp_on_read);
}

void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    suggested_size = 1500;
    buf->base = (char *) malloc(suggested_size);
    buf->len = suggested_size;
}

void udp_on_read(uv_udp_t *udp_socket_ptr, ssize_t packet_size, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (packet_size == PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH
        && memcmp(buf->base, MAGIC_WORD, 2) == 0
        && bytes_to_uint16(buf->base + PAYLOAD_LENGTH_INDEX) == packet_size
        && buf->base[PAYLOAD_TYPE_INDEX] == PAYLOAD_TYPE_ECHO
            ) {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr, src_ip, sizeof(src_ip));

        auto udp_packet_id = bytes_to_uint16(buf->base + PAYLOAD_ID_INDEX);
        auto udp_packet_seq = bytes_to_uint32(buf->base + PAYLOAD_SEQ_INDEX);

        update_peer_info(
                src_ip,
                IPPROTO_UDP,
                udp_packet_id,
                buf->base
        );

        udp_send(udp_packet_id, udp_packet_seq, addr);
    }

    free(buf->base);
}

void udp_send(uint16_t udp_packet_id, uint32_t udp_packet_seq, const struct sockaddr *dst_addr) {
    //封装udp包
    char send_buf[PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH] = {'\0'};
    memcpy(send_buf, MAGIC_WORD, 2);
    uint16_to_bytes(PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH, send_buf + PAYLOAD_LENGTH_INDEX);
    send_buf[PAYLOAD_TYPE_INDEX] = PAYLOAD_TYPE_ECHO_REPLY;
    uint16_to_bytes(udp_packet_id, send_buf + PAYLOAD_ID_INDEX);
    uint32_to_bytes(udp_packet_seq, send_buf + PAYLOAD_SEQ_INDEX);
    generate_random_str(send_buf + PAYLOAD_RANDOM_STR_INDEX, PAYLOAD_RANDOM_STR_LENGTH);

    uv_buf_t write_buf = uv_buf_init(send_buf, PAYLOAD_RANDOM_STR_INDEX + PAYLOAD_RANDOM_STR_LENGTH);
    int ret = 0;
    for (int i = 0; i < 3; i++) {
        ret = uv_udp_try_send(
                &udp_socket,
                &write_buf,
                1,
                dst_addr
        );
        if (ret < 0) {
            usleep(5);
        } else {
            break;
        }
    }

    if (ret < 0) {
        string dst_ip;
        dst_ip.assign(
                inet_ntoa(
                        ((sockaddr_in *) dst_addr)->sin_addr
                )
        );
        logger->error("Peer Host %s send udp packet fail!", dst_ip.data());
    }
}
