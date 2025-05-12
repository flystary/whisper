#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <string>

#include "version_config.h"
#include "config.h"
#include "sampling.h"
#include "http_server.h"

using std::to_string;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uv_loop_t *main_loop;

int main(int argc, char *argv[]) {
    bool is_daemon = true;

    if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            printf("%s\n", VERSION_BUILD_TIME);
            exit(0);
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("-d --daemon      : if false, running in the foreground. otherwise running in background by default\n");
            printf("-c --config-file : specify the configuration file\n");
            printf("-v --version     : output version information and exit\n");
            printf("-h --help        : display this help and exit\n");
            exit(0);
        }
    }

    whisper_config_file.assign(get_current_dir_name());
    whisper_config_file.append("/whisper_client.conf");

    for (int arg_index = 0; arg_index < argc; arg_index++) {
        if (strcmp(argv[arg_index], "-c") == 0 || strcmp(argv[arg_index], "--config-file") == 0) {
            if (arg_index + 1 < argc) {
                whisper_config_file.clear();
                whisper_config_file.assign(argv[arg_index + 1]);
                arg_index++;
            } else {
                printf("Config File NOT Found\n");
                exit(CONF_FILE_ERROR);
            }
        } else if ((strcmp(argv[arg_index], "-d") == 0 || strcmp(argv[arg_index], "--daemon") == 0)
                   && arg_index + 1 < argc
                   && strcmp(argv[arg_index + 1], "false") == 0
                ) {
            is_daemon = false;
            arg_index++;
        }
    }

    if (is_daemon) {
        if (daemon(1, 0) == -1) {
            exit(EXIT_FAILURE);
        }
    }

    setenv("UV_THREADPOOL_SIZE", to_string(peerConfigMap.size() * 3 + 10).data(), 1);
    srand(time(NULL));

    loadConfig();
    initLog4cpp();

    main_loop = uv_default_loop();

    init_icmp(main_loop);

    init_udp(main_loop);

    init_tcp(main_loop);

    init_http_server(main_loop);

    return uv_run(main_loop, UV_RUN_DEFAULT);
}
