#pragma once

#include <stddef.h>

int base64_encode(const void* buf, size_t size, char *str, size_t out_size);
int base64_decode(const char *s, size_t str_len, void *data, size_t data_len);
