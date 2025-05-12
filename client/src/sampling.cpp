#include "sampling.h"
#include "utility.h"
#include "icmp_sampling.h"

void init_peer_quality(PeerQuality *peer_quality) {
    uv_mutex_init(&peer_quality->uv_mutex);

    peer_quality->sampling_index = 0;
    for (uint16_t samplingIndex = 0; samplingIndex < 256; samplingIndex++) {
        peer_quality->sampling_tab[samplingIndex].send_time = 0;
        peer_quality->sampling_tab[samplingIndex].recv_time = 0;
        peer_quality->sampling_tab[samplingIndex].latency = -1;
    }

    peer_quality->avg_latency = -1;
    peer_quality->max_latency = -1;
    peer_quality->min_latency = -1;
    peer_quality->jitter = -1;
    peer_quality->loss_rate = -1;
    peer_quality->last_time = get_current_msec();
    peer_quality->status = false;
}

void record_peer_quality(const string &protocol, struct PeerConfig *peerConfig, string &src_ip, uint16_t packet_id, uint8_t packet_index) {
    PeerQuality *peer_quality;
    if (protocol == "icmp") {
        peer_quality = &peerConfig->icmp_quality;
    } else if (protocol == "tcp") {
        peer_quality = &peerConfig->tcp_quality;
    } else if (protocol == "udp") {
        peer_quality = &peerConfig->udp_quality;
    } else {
        return;
    }

    auto *peer_sampling = peer_quality->sampling_tab + packet_index;
    if (peer_sampling->latency != -1) {
        return;
    }

    uv_mutex_lock(&peer_quality->uv_mutex);

    uint64_t current_msec = get_current_msec();

    peer_quality->last_time = current_msec;

    peer_sampling->recv_time = current_msec;
    peer_sampling->latency = current_msec - peer_sampling->send_time;

    if (!peer_quality->status) {
        peer_quality->status = true;
        // logger->info("Peer %s is %s reachable", peerConfig->dst_host.c_str(), protocol.data());
        logger->info("%s src: %s dst: %s is reachable",
            protocol.data(),
            peerConfig->src_ip.data(),
            peerConfig->dst_host.c_str()
        );
    }

    uv_mutex_unlock(&peer_quality->uv_mutex);
}

void cal_peer_quality(PeerConfig *peer_config, const string &protocol, PeerQuality *peer_quality) {
    uint64_t current_msec = get_current_msec();

    uv_mutex_lock(&peer_quality->uv_mutex);

    auto *sampling_tab = peer_quality->sampling_tab;

    if (current_msec - peer_quality->last_time > peer_config->timeout) {
        if (peer_quality->status) {
            peer_quality->status = false;

            // logger->info("srcip : %s Peer %s is %s unreachable",
            //             peer_config->src_ip.data(),
            //             peer_config->dst_host.c_str(),
            //             protocol.data()
            // );
            logger->info("%s src: %s dst: %s is unreachable",
                protocol.data(),
                peer_config->src_ip.data(),
                peer_config->dst_host.c_str()
            );
        }
        // else
        // {
        //     logger->info("srcip : %s Peer %s is %s unreachable",
        //                 peer_config->src_ip.data(),
        //                 peer_config->dst_host.c_str(),
        //                 protocol.data()
        //     );
        // }
        peer_config->timeout_num++;
        if(peer_config->timeout_num >= 60 && peer_config->icmp){
            logger->info("%s src: %s dst: %s is timeout and 60 times",
                protocol.data(),
                peer_config->src_ip.data(),
                peer_config->dst_host.c_str()
            );
            init_icmp_sock(peer_config);
            peer_config->timeout_num = 0;
        }

        // logger->info("%s src: %s dst: %s is timeout_num is %d",
        //     protocol.data(),
        //     peer_config->src_ip.data(),
        //     peer_config->dst_host.c_str(),
        //     peer_config->timeout_num
        // );

//        for (uint16_t samplingIndex = 0; samplingIndex < 256; samplingIndex++) {
//            sampling_tab[samplingIndex].send_time = 0;
//            sampling_tab[samplingIndex].recv_time = 0;
//            sampling_tab[samplingIndex].latency = -1;
//        }
//
//        peer_quality->avg_latency = -1;
//        peer_quality->loss_rate = -1;
//        peer_quality->max_latency = -1;
//        peer_quality->min_latency = -1;
//        peer_quality->jitter = -1;
    } else {
        //计算平均延迟和丢包
        peer_config->timeout_num = 0;
        uint64_t total_latency = 0;
        uint16_t valid_latency_count = 0;

        uint32_t total_loss_count = 0;
        uint32_t valid_loss_count = 0;

        uint16_t count = 0;
        uint8_t sampling_index = peer_quality->sampling_index - 1;

        int32_t max_latency = -1;
        int32_t min_latency = -1;


        while (valid_loss_count < peer_config->sampling_range && count < 256) {
            if (sampling_tab[sampling_index].send_time != 0) {
                valid_loss_count++;
                if (sampling_tab[sampling_index].latency == -1
                    && current_msec - sampling_tab[sampling_index].send_time > peer_config->timeout) {
                    total_loss_count++;
                } else if (sampling_tab[sampling_index].latency >= 0) {
                    valid_latency_count++;
                    total_latency += sampling_tab[sampling_index].latency;

                    max_latency =
                            (sampling_tab[sampling_index].latency > max_latency || max_latency == -1)
                            ?
                            sampling_tab[sampling_index].latency
                            :
                            max_latency;

                    min_latency =
                            (sampling_tab[sampling_index].latency < min_latency || min_latency == -1)
                            ?
                            sampling_tab[sampling_index].latency
                            :
                            min_latency;
                }
            }
            count++;
            sampling_index--;
        }

        int32_t avg_latency = -1;
        int32_t jitter = -1;
        if (valid_latency_count > 0) {
            avg_latency = total_latency / valid_latency_count;
            jitter = max_latency - min_latency;
        }

        if (peer_quality->avg_latency != avg_latency) {
            // logger->info("The %s avg latency of Srcip: %s  to Peer: %s is CHANGED.  avg latency=%d->%d",
            //              protocol.data(),
            //              peer_config->src_ip.data(),
            //              peer_config->dst_host.data(),
            //              peer_quality->avg_latency,
            //              avg_latency
            // );
            logger->info("%s src: %s dst: %s avg_latency is changed: %d->%d",
                protocol.data(),
                peer_config->src_ip.data(),
                peer_config->dst_host.data(),
                peer_quality->avg_latency,
                avg_latency
            );            
            peer_quality->avg_latency = avg_latency;
        }

        if (peer_quality->max_latency != max_latency) {
            // logger->info("The %s max latency of Srcip: %s to Peer: %s is CHANGED.  max latency=%d->%d",
            //              protocol.data(),
            //              peer_config->src_ip.data(),
            //              peer_config->dst_host.data(),
            //              peer_quality->max_latency,
            //              max_latency
            // );
            logger->info("%s src: %s dst: %s max_latency is changed: %d->%d",
                protocol.data(),
                peer_config->src_ip.data(),
                peer_config->dst_host.data(),
                peer_quality->max_latency,
                max_latency
            );
            peer_quality->max_latency = max_latency;
        }


        if (peer_quality->min_latency != min_latency) {
            // logger->info("The %s min latency of Srcip: %s  to Peer: %s is CHANGED.  min latency=%d->%d",
            //              protocol.data(),
            //              peer_config->src_ip.data(),
            //              peer_config->dst_host.data(),
            //              peer_quality->min_latency,
            //              min_latency
            // );
            logger->info("%s src: %s dst: %s min_latency is changed: %d->%d",
                    protocol.data(),
                    peer_config->src_ip.data(),
                    peer_config->dst_host.data(),
                    peer_quality->min_latency,
                    min_latency
            );
            peer_quality->min_latency = min_latency;
        }

        if (peer_quality->jitter != jitter) {
            // logger->info("The %s jitter of Srcip :  %s Peer : %s is CHANGED.  jitter=%d->%d",
            //              protocol.data(),
            //              peer_config->src_ip.data(),
            //              peer_config->dst_host.data(),
            //              peer_quality->jitter,
            //              jitter
            // );
            logger->info("%s src: %s dst: %s jitter is changed: %d->%d",
                         protocol.data(),
                         peer_config->src_ip.data(),
                         peer_config->dst_host.data(),
                         peer_quality->jitter,
                         jitter
            );
            peer_quality->jitter = jitter;
        }

        int32_t loss_rate;
        if (valid_loss_count > 0) {
            loss_rate = total_loss_count * 1000 / valid_loss_count;
        } else {
            loss_rate = -1;
        }

        if (peer_quality->loss_rate != loss_rate) {
            // logger->warn("The %s loss rate of Srcip: %s to Peer %s is CHANGED. loss_rate=%d->%d",
            //              protocol.data(),
            //              peer_config->src_ip.data(),
            //              peer_config->dst_host.data(),
            //              peer_quality->loss_rate,
            //              loss_rate
            // );
            logger->warn("%s src: %s dst: %s loss_rate is changed: %d->%d",
                protocol.data(),
                peer_config->src_ip.data(),
                peer_config->dst_host.data(),
                peer_quality->loss_rate,
                loss_rate
            );
            peer_quality->loss_rate = loss_rate;
        }
    }

    uv_mutex_unlock(&peer_quality->uv_mutex);
}

void print_peer_quality(Json::Value &json_peer_quality, PeerQuality *peer_quality) {
    uv_mutex_lock(&peer_quality->uv_mutex);

    json_peer_quality["status"] = peer_quality->status ? "reachable" : "unreachable";

    time_t time = peer_quality->last_time / 1000;
    char buffer[128] = {'\0'};
    strftime(buffer, 128, "%Y-%m-%d %H:%M:%S", localtime(&time));
    string date_time;
    date_time.assign(buffer);
    date_time.append(".").append(to_string(peer_quality->last_time % 1000));
    json_peer_quality["lastRecvTime"] = date_time;

    if (peer_quality->status) {
        json_peer_quality["avgLatency"] = peer_quality->avg_latency;
        json_peer_quality["maxLatency"] = peer_quality->max_latency;
        json_peer_quality["minLatency"] = peer_quality->min_latency;
        json_peer_quality["jitter"] = peer_quality->jitter;
        json_peer_quality["lossRate"] = peer_quality->loss_rate;
    }

    uv_mutex_unlock(&peer_quality->uv_mutex);
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
