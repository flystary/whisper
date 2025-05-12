#ifndef WHISPER_CLIENT_UTILITY_H
#define WHISPER_CLIENT_UTILITY_H

#include "config.h"

uint64_t get_current_msec();

void uint32_to_bytes(uint32_t i, char *bytes);

uint32_t bytes_to_uint32(const char *bytes);

void uint16_to_bytes(uint16_t i, char *bytes);

uint16_t bytes_to_uint16(const char *bytes);

void generate_random_str(char *str, const int length);

#endif //WHISPER_CLIENT_UTILITY_H
