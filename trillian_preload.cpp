/*
 * Trillian IMPP for libpurple/Pidgin
 * Copyright (c) 2017 Konstantin Kharlamov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/ssl.h>
#include "protocol.h"

extern "C"
int SSL_read(SSL *ssl, void *b, int num) {
    uint8_t* buf = (uint8_t*)b;
    int (*original)(SSL *ssl, uint8_t *buf, int num) = (int (*)(SSL *, uint8_t *, int))dlsym(RTLD_NEXT, "SSL_read");
    if (!original) {
        fprintf(stderr, "Oops!");
        abort();
    }
    int ret = (*original)(ssl, buf, num);
    printf("SSL_read: %d bytes read, content is:\n", ret);
    if (ret > 0)
        print_tlv_packet(buf, (uint)ret);
    return ret;
}

extern "C"
int SSL_write(SSL *ssl, const void *b, int num) {
    const uint8_t* buf = (uint8_t*)b;
    int (*original)(SSL *ssl, const uint8_t *buf, int num) = (int (*)(SSL *, const uint8_t *, int))dlsym(RTLD_NEXT, "SSL_write");
    if (!original) {
        fprintf(stderr, "Oops!");
        abort();
    }
    int ret = (*original)(ssl, buf, num);
    printf("SSL_write: %d bytes write, content is:\n", ret);
    if (ret > 0)
        print_tlv_packet(buf, (uint)ret);
    return ret;
}
