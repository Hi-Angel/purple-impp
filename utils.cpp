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

#include <string>
#include <cassert>
#include <cstring>
#include <zlib.h>
#include "utils.h"

const char* strerror_newl(int err) {
    return (strerror(err) + std::string{"\n"}).c_str();
}

std::pair<int,z_stream> inflate(const z_stream& s, bool doInit) {
    int ret;
    z_stream strm = s;
    if (doInit) {
        strm.zalloc    = Z_NULL;
        strm.zfree     = Z_NULL;
        strm.opaque    = Z_NULL;
        // strm.avail_in  = src_sz;
        // strm.next_in   = (uint8_t*)src; // AFAIK the data shouldn't be touched
        // strm.avail_out = dst_sz;
        // strm.next_out  = dst;
        ret = inflateInit(&strm);
        if (ret != Z_OK)
            return {ret, strm};
    }

    /* decompress until deflate stream ends or EOF */
    do {
        if (strm.avail_in == 0) // EOF implies having more data somewhere
            break;

        /* run inflate() on input until output buffer not full */
        do {
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR;     /* fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    inflateEnd(&strm);
                    return {ret, strm};
                case Z_BUF_ERROR: /* not enough output space. In general not fatal */
                    return {ret, strm};
            }
        } while (strm.avail_out == 0);
    } while (ret != Z_STREAM_END); /* done when inflate() says it's done */

    /* clean up and return */
    inflateEnd(&strm);
    return {ret, strm};
}

std::pair<int,std::vector<uint8_t>> inflate(const std::vector<uint8_t> in) {
    std::vector<uint8_t> out(in.size());
    z_stream strm;
    strm.next_in   = (uint8_t*)in.data(); // AFAIK the data shouldn't be touched
    strm.avail_in  = in.size();
    strm.next_out  = &out[0];
    strm.avail_out = out.size();
    bool doInit = true;
    for(;;) {
        std::pair<int,z_stream> ret = inflate(strm, doInit);
        uint written = out.size() - ret.second.avail_out;
        if (ret.first == Z_BUF_ERROR) {
            strm = ret.second;
            out.resize(out.size() + 256);
            strm.next_out  = &out[written];
            strm.avail_out = out.size() - written;
            doInit = false;
        } else if (ret.first < 0) {
            return {ret.first, out};
        } else {
            out.resize(written);
            return {ret.first, out};
        }
    }
}

void zerror(int zlib_ret) {
    fputs("zpipe: ", stderr);
    switch (zlib_ret) {
        case Z_STREAM_ERROR:
            fputs("invalid compression level\n", stderr);
            break;
        case Z_DATA_ERROR:
            fputs("invalid or incomplete deflate data\n", stderr);
            break;
        case Z_MEM_ERROR:
            fputs("out of memory\n", stderr);
            break;
        case Z_VERSION_ERROR:
            fputs("zlib version mismatch!\n", stderr);
            break;
        case Z_BUF_ERROR:
            fputs("zlib not enough output space!\n", stderr);
            break;
        default:
            fprintf(stderr, "unknown zlib error %d\n", zlib_ret);
    }
}
