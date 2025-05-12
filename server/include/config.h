#ifndef WHISPER_SERVER_CONFIG_H
#define WHISPER_SERVER_CONFIG_H

#include <string>

#include <log4cpp/Category.hh>
#include <libconfig.h++>
#include <uv.h>

using std::string;

const char MAGIC_WORD[] = "7x";

enum EXIT_CODE {
    CONF_FILE_ERROR = 1,
    UDP_UV_SOCKET_ERROR,
    TCP_RAW_SOCKET_ERROR,
    ADDR_CONFIG_ERROR,
    IPTABLES_CONFIG_ERROR
};

extern log4cpp::Category *logger;

extern libconfig::Config whisperCfg;

extern string whisper_config_file;
extern string log4cpp_config_file;

extern string listen_ip;
extern int udp_port;
extern int tcp_port;
extern int http_port;

void initLog4cpp();

void loadConfig();

#endif //WHISPER_SERVER_CONFIG_H
