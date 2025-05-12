#include <unistd.h>
#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/PatternLayout.hh>

#include "config.h"

log4cpp::Category *logger;
libconfig::Config whisperCfg;

string whisper_config_file;
string log4cpp_config_file;

string listen_ip;
int udp_port;
int tcp_port;
int http_port;

void checkConfigKey(libconfig::Config *config, const string &key);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// void initLog4cpp() {
//     char *pwd = get_current_dir_name();
//     try {
//         log4cpp::PropertyConfigurator::configure(log4cpp_config_file);
//         logger = &log4cpp::Category::getRoot();
//     } catch (log4cpp::ConfigureFailure &f) {
//         string logFile;
//         logFile.assign(pwd);
//         logFile.append("whisper_server.log");

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
        auto *defaultAppender = new log4cpp::RollingFileAppender("RollingFileAppender", "/var/log/whisper_server.log", 50 * 1024 * 1024, 7, true, 00644);
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
        whisperCfg.lookupValue("listen_ip", log4cpp_config_file);

        checkConfigKey(&whisperCfg, "listen_ip");
        whisperCfg.lookupValue("listen_ip", listen_ip);

        checkConfigKey(&whisperCfg, "http_port");
        http_port = whisperCfg.lookup("http_port");

        checkConfigKey(&whisperCfg, "udp_port");
        udp_port = whisperCfg.lookup("udp_port");

        checkConfigKey(&whisperCfg, "tcp_port");
        tcp_port = whisperCfg.lookup("tcp_port");

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
