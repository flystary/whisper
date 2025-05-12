#include <unistd.h>
#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/PatternLayout.hh>

#include "config.h"
#include "sampling.h"

using std::to_string;

log4cpp::Category *logger;
libconfig::Config whisperCfg;

string whisper_config_file;
string log4cpp_config_file;

int http_port;

int id_bg = 0;
int id_end = 0;
bool id_set = false;
int id_index = 0;
int peer_icmp_num = 0;

bool open_icmp = false;
bool open_tcp = false;
bool open_udp = false;

string identity;

map<string, struct PeerConfig *> peerConfigMap;

void checkConfigKey(libconfig::Config *config, const string &key);

void checkConfigKey(libconfig::Setting *configSetting, int index, const string &key);

bool checkConfigID(libconfig::Config *config);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// void initLog4cpp() {
//     char *pwd = get_current_dir_name();
//     try {
//         log4cpp::PropertyConfigurator::configure(log4cpp_config_file);
//         logger = &log4cpp::Category::getRoot();
//     } catch (log4cpp::ConfigureFailure &f) {
//         string logFile;
//         logFile.assign(pwd);
//         logFile.append("whisper_client.log");

//         auto *defaultAppender = new log4cpp::RollingFileAppender("RollingFileAppender", logFile, 50 * 1024 * 1024, 7, true, 00644);
//         auto *defaultLayout = new log4cpp::PatternLayout();
//         defaultLayout->setConversionPattern("%d{%Y-%m-%d %H:%M:%S} [%t] [%p] %m%n");

//         logger = &log4cpp::Category::getInstance("root");

//         defaultAppender->setLayout(defaultLayout);
//         logger->setAppender(defaultAppender);
//         logger->setPriority(log4cpp::Priority::DEBUG);
//     }
//     free(pwd);
// }


void initLog4cpp()
{
    try
    {
        log4cpp::PropertyConfigurator::configure(log4cpp_config_file);

        // return log4cpp::Category::getRoot();
        logger = &log4cpp::Category::getRoot();
    }
    catch (log4cpp::ConfigureFailure &f)
    {
        auto *defaultAppender = new log4cpp::RollingFileAppender("RollingFileAppender", "/var/log/whisper_client.log", 50 * 1024 * 1024, 7, true, 00644);
        auto *defaultLayout = new log4cpp::PatternLayout();
        defaultLayout->setConversionPattern("%d{%Y-%m-%d %H:%M:%S} [%p]: [%c] %m%n");

        log4cpp::Category &category = log4cpp::Category::getInstance("root");

        defaultAppender->setLayout(defaultLayout);
        category.setAppender(defaultAppender);
        category.setPriority(log4cpp::Priority::INFO);

        logger = &category;
        // return category;
    }
}


void loadConfig() {
    try {
        if (access(whisper_config_file.c_str(), R_OK) != 0) {
            printf("Configuration file read fail. \n");
            exit(CONF_FILE_ERROR);
        }

        whisperCfg.readFile(whisper_config_file.c_str());

        checkConfigKey(&whisperCfg, "log4cpp_config_file");
        log4cpp_config_file.assign(whisperCfg.lookup("log4cpp_config_file").c_str());

        checkConfigKey(&whisperCfg, "http_port");
        http_port = whisperCfg.lookup("http_port");

        if (checkConfigID(&whisperCfg)) {
            id_bg = whisperCfg.lookup("begin_id");
            id_end = whisperCfg.lookup("end_id");
            if (id_bg < id_end) {
                id_set = true;
                id_index = id_bg;
                
            }
        }

        checkConfigKey(&whisperCfg, "identity");
        whisperCfg.lookupValue("identity", identity);
        if (identity.length() > 31) {
            printf("identity is invalid in configuration file. \n");
            exit(CONF_FILE_ERROR);
        }

        checkConfigKey(&whisperCfg, "peer");
        auto &peer = whisperCfg.lookup("peer");
        if (peer.getLength() == 0) {
            printf("Peer List is empty in configuration file. \n");
            exit(CONF_FILE_ERROR);
        }
        //检查多少个配置开启icmp
        for (int i = 0; i < peer.getLength(); i++){
            string enable_icmp_num;
            checkConfigKey(&peer, i, "icmp");
            peer[i].lookupValue("icmp", enable_icmp_num);
            if(enable_icmp_num == "enable"){
                peer_icmp_num++;
            }
        }
        int id_ave = 2;
        if(id_set&&peer_icmp_num>0){
            id_ave = (id_end-id_bg + 1) / peer_icmp_num;
        }
        if(id_ave < 2){
            printf("id_begin and id_end in id_ave is not enough.");
            exit(CONF_FILE_ERROR);
        }
        for (int i = 0; i < peer.getLength(); i++) {
            auto *peerConfig = new PeerConfig;

            checkConfigKey(&peer, i, "dst_host");
            peer[i].lookupValue("dst_host", peerConfig->dst_host);

            checkConfigKey(&peer, i, "src_ip");
            peer[i].lookupValue("src_ip", peerConfig->src_ip);

            checkConfigKey(&peer, i, "interval");
            peer[i].lookupValue("interval", peerConfig->interval);

            checkConfigKey(&peer, i, "timeout");
            peer[i].lookupValue("timeout", peerConfig->timeout);

            checkConfigKey(&peer, i, "sampling_range");
            peer[i].lookupValue("sampling_range", peerConfig->sampling_range);

            string enable_icmp;
            checkConfigKey(&peer, i, "icmp");
            peer[i].lookupValue("icmp", enable_icmp);
            peerConfig->icmp = (enable_icmp == "enable");
            open_icmp |= peerConfig->icmp;

            if(peerConfig->icmp && id_set && id_bg <= (id_end - id_ave +1)){
                peerConfig->id_bg   = id_bg;
                peerConfig->id_end  = id_bg + id_ave - 1;
                peerConfig->id_index = id_bg;   
                id_bg = id_bg +  id_ave;
            }

            string enable_tcp;
            checkConfigKey(&peer, i, "tcp");
            peer[i].lookupValue("tcp", enable_tcp);
            peerConfig->tcp = (enable_tcp == "enable");
            open_tcp |= peerConfig->tcp;

            if (peerConfig->tcp) {
                checkConfigKey(&peer, i, "tcp_port");
                peer[i].lookupValue("tcp_port", peerConfig->tcp_port);
                if (peerConfig->tcp_port < 1 || peerConfig->tcp_port > 65535) {
                    logger->error("TCP PORT in Peer %d is invalid.", i);
                    exit(CONF_FILE_ERROR);
                }

            } else {
                peerConfig->tcp_port = 0;
            }

            string enable_udp;
            checkConfigKey(&peer, i, "udp");
            peer[i].lookupValue("udp", enable_udp);
            peerConfig->udp = (enable_udp == "enable");
            open_udp |= peerConfig->udp;

            if (peerConfig->udp) {
                checkConfigKey(&peer, i, "udp_port");
                peer[i].lookupValue("udp_port", peerConfig->udp_port);
                if (peerConfig->udp_port < 1 || peerConfig->udp_port > 65535) {
                    logger->error("UDP PORT in Peer %d is invalid.", i);
                    exit(CONF_FILE_ERROR);
                }
            } else {
                peerConfig->udp_port = 0;
            }

            peerConfig->flow_id = rand() % (65535 - 2048) + 1024;
            peerConfig->src.sin_family = AF_INET;
            peerConfig->src.sin_port = htons(peerConfig->flow_id);

            peerConfig->udp_src.sin_family = AF_INET;
            peerConfig->udp_src.sin_port = htons(peerConfig->flow_id);
            // if (id_set && id_index >= id_bg && id_index <= id_end) {
            //     peerConfig->flow_id = htons(id_index++);
            // }

            if (id_set && peerConfig->icmp ) {
                peerConfig->flow_id = htons(peerConfig->id_index++);
            }

            if (inet_pton(AF_INET, peerConfig->src_ip.data(), &peerConfig->src.sin_addr) != 1) {
                printf("source IP configuration failed\n");
                exit(CONF_FILE_ERROR);
            }

            if (inet_pton(AF_INET, peerConfig->src_ip.data(), &peerConfig->udp_src.sin_addr) != 1) {
                printf("source IP configuration failed\n");
                exit(CONF_FILE_ERROR);
            }

            peerConfigMap.insert(map<string, PeerConfig *>::value_type(peerConfig->dst_host + ":" + to_string(peerConfig->flow_id), peerConfig));
        }

    } catch (const libconfig::ParseException &parseException) {
        printf("Parse error at %s: %d - %s \n", parseException.getFile(), parseException.getLine(), parseException.getError());
        exit(CONF_FILE_ERROR);
    }
}

void checkConfigKey(libconfig::Config *config, const string &key) {
    if (!config->exists(key)) {
        printf("%s not found in configuration file.", key.c_str());
        exit(CONF_FILE_ERROR);
    }
}

void checkConfigKey(libconfig::Setting *configSetting, int index, const string &key) {
    if (!(*configSetting)[index].exists(key)) {
        printf("%s not found in peer settings %d .", key.c_str(), index);
        exit(CONF_FILE_ERROR);
    }
}

bool checkConfigID(libconfig::Config *config) {
    if (config->exists("begin_id") && config->exists("end_id")) {
        printf("id_begin and id_end  in configuration file. \n");
        return true;
    }
    return false;
}
