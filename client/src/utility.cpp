#include <sys/timeb.h>
#include <uv.h>

#include "utility.h"

using std::to_string;

uint64_t get_current_msec() {
    uv_timeval64_t current;
    uv_gettimeofday(&current);
    return 1000ul * current.tv_sec + current.tv_usec / 1000;
}


void uint32_to_bytes(uint32_t i, char *bytes) {
    bytes[3] = 0xff & i;
    bytes[2] = 0xff & i >> 8;
    bytes[1] = 0xff & i >> 16;
    bytes[0] = 0xff & i >> 24;
}

uint32_t bytes_to_uint32(const char *bytes) {
    uint32_t i = 0;
    for (int index = 0; index < 4; index++) {
        uint32_t temp = (unsigned char) bytes[index];
        i += (temp << ((3 - index) * 8));
    }
    return i;
}

void uint16_to_bytes(uint16_t i, char *bytes) {
    bytes[1] = 0xff & i;
    bytes[0] = 0xff & i >> 8;
}

uint16_t bytes_to_uint16(const char *bytes) {
    uint16_t i = 0;
    for (int index = 0; index < 2; index++) {
        uint16_t temp = (unsigned char) bytes[index];
        i += (temp << ((1 - index) * 8));
    }
    return i;
}

void generate_random_str(char *str, const int length) {
    timeb currentTime;
    ftime(&currentTime);

    srand(currentTime.millitm);
    int i;
    for (i = 0; i < length; ++i) {
        switch ((rand() % 3)) {
            case 1:
                str[i] = 'A' + rand() % 26;
                break;
            case 2:
                str[i] = 'a' + rand() % 26;
                break;
            default:
                str[i] = '0' + rand() % 10;
                break;
        }
    }
}
