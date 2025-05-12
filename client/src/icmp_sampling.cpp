#include <cstring>

#include <netinet/ip_icmp.h>
#include <unistd.h>
#include<string>

#include "sampling.h"
#include "config.h"
#include "utility.h"
#include "icmp_sampling.h"

#define ICMP_LENGTH 64
#define PACKET_SEND_MAX_NUM 256

using std::to_string;

int tal_icmp_recv_socket = -1;

int sock_raw = 0;

// void init_icmp_sock(PeerConfig *peerConfig);

void icmp_read_work(uv_work_t *icmp_read_work_req);

void icmp_timer_task(uv_timer_t *icmp_timer);

void icmp_send(PeerConfig *peerConfig);

void icmp_pack(struct icmp *icmp_hdr, uint16_t id, uint16_t seq, int length);

bool icmp_unpack(char *buf, int len, uint16_t &icmp_packet_seq, uint16_t &icmp_packet_id, string &src_ip);

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

void init_icmp_sock(PeerConfig *peerConfig){
        if (open_icmp) {
            if (peerConfig->icmp) {
                uv_mutex_lock(&peerConfig->icmp_uv_mutex);
                close(peerConfig->icmp_send_socket);
                peerConfig->icmp_send_socket = -1;
                // auto temp = peerConfigMap.find(peerConfig->src_ip + ":" + to_string(peerConfig->flow_id));
                // if(temp == peerConfigMap.end())
                // {   
                //     logger->error("icmp socket init find  peerConfig failed"+ peerConfig->src_ip + ":" + to_string(peerConfig->flow_id));
                //     return ;
                // }
                // peerConfigMap.erase(peerConfig->src_ip + ":" + to_string(peerConfig->flow_id));
                // peerConfig->flow_id = htons(peerConfig->id_index++);
                // peerConfigMap.insert(map<string, PeerConfig *>::value_type(peerConfig->dst_host + ":" + to_string(peerConfig->flow_id), peerConfig));

                if(sock_raw == 1)
                {
                    peerConfig->icmp_send_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
                    // peerConfig->icmp_recv_socket = tal_icmp_recv_socket;
                    int id = rand() % (65535 - 2048) + 1024;

                    peerConfig->src.sin_port = htons(id);

                    auto temp = peerConfigMap.find(peerConfig->dst_host + ":" + to_string(peerConfig->flow_id));
                    if(temp == peerConfigMap.end())
                    {   
                        logger->error("icmp socket init find  peerConfig failed"+ peerConfig->src_ip + ":" + to_string(peerConfig->flow_id));
                        return ;
                    }
                    peerConfigMap.erase(peerConfig->dst_host + ":" + to_string(peerConfig->flow_id));
                    peerConfig->flow_id = htons(peerConfig->id_index++);
                    peerConfigMap.insert(map<string, PeerConfig *>::value_type(peerConfig->dst_host + ":" + to_string(peerConfig->flow_id), peerConfig));
                }
                else
                {
                    // close(peerConfig->icmp_recv_socket);
                    peerConfig->icmp_send_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
                    peerConfig->icmp_recv_socket = peerConfig->icmp_send_socket;
                }
                
                if( peerConfig->icmp_send_socket<0){
                    logger->error("icmp socket init creation failed");
                    logger->error("icmp socket init creation failed !  srcip: %s , dstip: %s ",
                        peerConfig->src_ip.data(),
                        peerConfig->dst_host.data()
                    );
                }

                bind(peerConfig->icmp_send_socket, (sockaddr *) &peerConfig->src, sizeof(sockaddr));

                // init_peer_quality(&peerConfig->icmp_quality);
                uv_mutex_unlock(&peerConfig->icmp_uv_mutex);
                logger->debug("icmp_send_socket  = " + std::to_string(peerConfig->icmp_send_socket));
                logger->debug("icmp socket init creation ok !  srcip: %s , dstip: %s ",
                        peerConfig->src_ip.data(),
                        peerConfig->dst_host.data()
                );
            }
        // }
        // printf("sock_raw = %d \n",sock_raw);
        logger->debug("init_icmp_sock sock_raw  " + std::to_string(sock_raw));
    }
}





void init_icmp(uv_loop_t *main_loop) {
    if (open_icmp) {
        tal_icmp_recv_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
        if (tal_icmp_recv_socket == -1) {
            logger->error("icmp socket creation failed");
            exit(ICMP_RAW_SOCKET_ERROR);
        }

        for (auto &it: peerConfigMap) {
            auto *peerConfig = it.second;
            if (peerConfig->icmp) {
                peerConfig->icmp_dst.sin_family = AF_INET;
                peerConfig->icmp_dst.sin_port = htons(0);
                if (inet_pton(AF_INET, peerConfig->dst_host.data(), &peerConfig->icmp_dst.sin_addr) != 1) {
                    logger->error("icmp destination IP %s configuration failed");
                    exit(DST_ADDR_CONFIG_ERROR);
                }

                
                peerConfig->icmp_send_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
                if (peerConfig->icmp_send_socket == -1) {
                    // 如果创建套接字失败，打印错误码
                    perror("socket creation IPPROTO_ICMP failed \n");
                    printf("Error code: %d\n", errno);
                    
                    logger->error("icmp socket creation SOCK_DGRAM IPPROTO_ICMP failed Error code: %d\n",errno);
                }
                peerConfig->icmp_recv_socket = peerConfig->icmp_send_socket;
                
                if(sock_raw == 1 && peerConfig->icmp_send_socket>0 ||(sock_raw == -1 && peerConfig->icmp_send_socket<0)){
                    logger->error("icmp socket creation failed");
                    logger->error("icmp socket creation icmp_send_socket = " + std::to_string(peerConfig->icmp_send_socket)+"sock_raw =  "+std::to_string(sock_raw));
                }
                
                if( peerConfig->icmp_send_socket == -1){
                    peerConfig->icmp_send_socket = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
                    peerConfig->icmp_recv_socket = tal_icmp_recv_socket;
                    int id = rand() % (65535 - 2048) + 1024;

                    peerConfig->src.sin_port = htons(id);
                    sock_raw = 1;
                }
                else{
                    sock_raw = -1;
                    peerConfig->src.sin_port = htons(0);
                }


                // peerConfig->icmp_recv_socket =  peerConfig->icmp_send_socket;
                if (peerConfig->icmp_send_socket == -1) {
                    logger->error("icmp socket creation failed ,need exit ");
                    exit(ICMP_RAW_SOCKET_ERROR);
                }

                uv_mutex_init(&peerConfig->icmp_uv_mutex);

                bind(peerConfig->icmp_send_socket, (sockaddr *) &peerConfig->src, sizeof(sockaddr));

                init_peer_quality(&peerConfig->icmp_quality);
                logger->debug("icmp_send_socket  " + std::to_string(peerConfig->icmp_send_socket));
                uv_timer_init(main_loop, &peerConfig->icmp_uv_timer);
                peerConfig->icmp_uv_timer.data = peerConfig;
                uv_timer_start(
                        &peerConfig->icmp_uv_timer,
                        icmp_timer_task,
                        rand() % peerConfig->interval,
                        peerConfig->interval
                );
            }
        }
        printf("sock_raw = %d \n",sock_raw);
        logger->debug("sock_raw  " + std::to_string(sock_raw));
        auto *icmp_uv_work = new uv_work_t;
        uv_queue_work(main_loop, icmp_uv_work, icmp_read_work, nullptr);
    }

}

void icmp_read_work(uv_work_t *icmp_read_work_req) {
    fd_set read_fd;
    char recv_buf[512];

    while (true) {
        memset(recv_buf, 0, sizeof(recv_buf));
        FD_ZERO(&read_fd);
        
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = 1;
        int max = -1;
        int ret = -1;
        if(sock_raw  != 1){
            for (auto &it: peerConfigMap) {
                auto *peerConfig = it.second;
                if(peerConfig->icmp_recv_socket>0 && peerConfig->icmp ){
                    FD_SET(peerConfig->icmp_recv_socket, &read_fd);
                    max =  max < peerConfig->icmp_recv_socket ? peerConfig->icmp_recv_socket : max;
                }
            }
             ret = select(max + 1, &read_fd, NULL, NULL, &tv);
        }
        else{
            FD_SET(tal_icmp_recv_socket, &read_fd);
             ret = select(tal_icmp_recv_socket + 1, &read_fd, NULL, NULL, &tv);
        }
 

        // int ret = select(max, &read_fd, NULL, NULL, &tv);
        switch (ret) {
            case -1:
                logger->error("fail to select icmp socket!");
                break;
            case 0:
                break;
            default: {
                if(sock_raw!=1){
                    ssize_t size = 0;
                    // do {
                    for (auto &it: peerConfigMap) {
                        auto *peerConfig = it.second;

                        // if(FD_ISSET(peerConfig->icmp_recv_socket, &read_fd)){
                        uv_mutex_lock(&peerConfig->icmp_uv_mutex);
                        if(peerConfig->icmp && peerConfig->icmp_recv_socket > 0 && FD_ISSET(peerConfig->icmp_recv_socket, &read_fd)){

                            size = recv(peerConfig->icmp_recv_socket, recv_buf, sizeof(recv_buf), 0);
                            if (size > 0) {
                                // 对接收的包进行解封
                                uint16_t packet_seq = 0;
                                uint16_t packet_id = 0;
                                string src_ip;
                                if (!icmp_unpack(recv_buf, size, packet_seq, packet_id, src_ip)) {
                                    continue;
                                }
                                if(src_ip.empty()){
                                    src_ip = peerConfig->dst_host;
                                }
                                auto it = peerConfigMap.find(src_ip + ":" + to_string(peerConfig->flow_id));
                                if (it == peerConfigMap.end()) {
                                    continue;
                                }

                                auto *peerConfigt = it->second;

                                record_peer_quality("icmp", peerConfigt, src_ip, packet_id, packet_seq % 256);
                            }
                        }
                        uv_mutex_unlock(&peerConfig->icmp_uv_mutex);
                        }
                    // } while (size > 0);
                    break;  
                }
                else{

                ssize_t size = 0;
                    do {
                        size = recv(tal_icmp_recv_socket, recv_buf, sizeof(recv_buf), 0);
                        if (size > 0) {
                            // 对接收的包进行解封
                            uint16_t packet_seq = 0;
                            uint16_t packet_id = 0;
                            string src_ip;
                            if (!icmp_unpack(recv_buf, size, packet_seq, packet_id, src_ip)) {
                                continue;
                            }
                            
                            auto it = peerConfigMap.find(src_ip + ":" + to_string(packet_id));
                            if (it == peerConfigMap.end()) {
                                continue;
                            }

                            auto *peerConfig = it->second;

                            record_peer_quality("icmp", peerConfig, src_ip, packet_id, packet_seq % 256);
                        }
                    } while (size > 0);
                    break;
                }
                
            }
        }
    }
}

void icmp_timer_task(uv_timer_t *icmp_timer) {
    auto *peerConfig = (struct PeerConfig *) icmp_timer->data;

    //计算连通性、延迟和丢包
    cal_peer_quality(
            peerConfig,
            "icmp",
            &peerConfig->icmp_quality
    );

    //发送ICMP ECHO
    icmp_send(peerConfig);
}

void icmp_send(PeerConfig *peerConfig) {
    auto *peer_quality = &peerConfig->icmp_quality;

    if(peer_quality->sampling_index == 0){
        init_icmp_sock(peerConfig);
    }

    uv_mutex_lock(&peer_quality->uv_mutex);

    peer_quality->sampling_tab[peer_quality->sampling_index].send_time = get_current_msec();
    peer_quality->sampling_tab[peer_quality->sampling_index].recv_time = 0;
    peer_quality->sampling_tab[peer_quality->sampling_index].latency = -1;

    

    //封装icmp包
    char send_buf[128];
    memset(send_buf, 0, sizeof(send_buf));
    icmp_pack(
            (struct icmp *) send_buf,
            peerConfig->flow_id,
            peer_quality->sampling_index,
            ICMP_LENGTH
    );

    // if(peer_quality->sampling_index == 255){
    //     init_icmp_sock(peerConfig);
    // }

    peer_quality->sampling_index++;

    uv_mutex_unlock(&peer_quality->uv_mutex);

    ssize_t send_ret = 0;
    for (int i = 0; i < 3; i++) {
        send_ret = sendto(peerConfig->icmp_send_socket, send_buf, ICMP_LENGTH, 0, (struct sockaddr *) &peerConfig->icmp_dst, sizeof(struct sockaddr));
        if (send_ret < 0) {
            usleep(5);
        } else {
            break;
        }
    }
    if (send_ret < 0) {
        logger->error("Peer Src_ip: %s Peer Host: %s send icmp packet fail!", peerConfig->src_ip.data(),peerConfig->dst_host.data());
    }

    // if(peer_quality->sampling_index == 0){
    //     init_icmp_sock(peerConfig);
    // }

}

void icmp_pack(struct icmp *icmp_hdr, uint16_t id, uint16_t seq, int length) {
    int i = 0;
    //类型填回送请求
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    //注意，这里先填写0，很重要！
    icmp_hdr->icmp_cksum = 0;
    //这里的序列号我们填1,2,3,4....
    icmp_hdr->icmp_seq = htons(seq);
    //我们使用pid作为icmp_id,icmp_id只是2字节，而pid有4字节
    icmp_hdr->icmp_id = id;

    for (i = 0; i < length; i++) {
        //填充数据段，使ICMP报文大于64B
        icmp_hdr->icmp_data[i] = i;
    }

    //校验和计算
    icmp_hdr->icmp_cksum = checksum((char *) icmp_hdr, length);
}

bool icmp_unpack(char *buf, int len, uint16_t &icmp_packet_seq, uint16_t &icmp_packet_id, string &src_ip) {
    struct icmp *icmp = NULL;
    if(sock_raw == 1){
        int iphdr_len;

        struct ip *ip_hdr = (struct ip *) buf;
        iphdr_len = ip_hdr->ip_hl * 4;

        //使指针跳过IP头指向ICMP头
        icmp = (struct icmp *) (buf + iphdr_len);

        //icmp包长度
        len -= iphdr_len;
        src_ip.assign(inet_ntoa(ip_hdr->ip_src));
    }else{
        icmp = (struct icmp *) (buf);
    }
     

    //判断长度是否为ICMP包长度
    if (len < 8) {
        logger->error("Invalid icmp packet.Its length is less than 8");
        return false;
    }

    //判断该包是ICMP回送回答包且该包是我们发出去的
    if (icmp->icmp_type != ICMP_ECHOREPLY) {
        return false;
    }

    icmp_packet_seq = ntohs(icmp->icmp_seq);
    if ((icmp_packet_seq < 0) || (icmp_packet_seq > PACKET_SEND_MAX_NUM)) {
        return false;
    }

    icmp_packet_id = icmp->icmp_id;
    // printf("icmp_packet_id %d \n",icmp_packet_id);
    // printf("icmp_packet_seq %d \n",icmp_packet_seq);

    return true;
}
