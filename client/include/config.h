#ifndef WHISPER_CLIENT_CONFIG_H
#define WHISPER_CLIENT_CONFIG_H

#include <string>
#include <list>

#include <log4cpp/Category.hh>
#include <libconfig.h++>
#include <uv.h>

using std::string;
using std::to_string;
using std::map;

const char MAGIC_WORD[] = "7x";

enum EXIT_CODE {
    CONF_FILE_ERROR = 1,
    ICMP_RAW_SOCKET_ERROR,
    UDP_RAW_SOCKET_ERROR,
    TCP_RAW_SOCKET_ERROR,
    DST_ADDR_CONFIG_ERROR,
    IPTABLES_CONFIG_ERROR
};
extern log4cpp::Category *logger;

extern libconfig::Config whisperCfg;

extern string whisper_config_file;
extern string log4cpp_config_file;

extern int http_port;

extern bool open_icmp;
extern bool open_tcp;
extern bool open_udp;

extern string identity;

extern map<string, struct PeerConfig *> peerConfigMap;

void initLog4cpp();

void loadConfig();

#endif //WHISPER_CLIENT_CONFIG_H
