#include <string>
#include <cassert>
#include <cstring>
#include <zlib.h>
#include "utils.h"

const char* strerror_newl(int err) {
    return (strerror(err) + std::string{"\n"}).c_str();
}

int inflate(const uint8_t* src, unsigned src_sz, uint8_t* dst, unsigned dst_sz) {
    z_stream strm;

    /* allocate inflate state */
    strm.zalloc    = Z_NULL;
    strm.zfree     = Z_NULL;
    strm.opaque    = Z_NULL;
    strm.avail_in  = src_sz;
    strm.next_in   = (uint8_t*)src; // AFAIK the data shouldn't be touched
    strm.avail_out = dst_sz;
    strm.next_out  = dst;
    int ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;

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
                case Z_BUF_ERROR: /* not enough output space. In general not fatal */
                    inflateEnd(&strm);
                    return ret;
            }
        } while (strm.avail_out == 0);
    } while (ret != Z_STREAM_END); /* done when inflate() says it's done */

    /* clean up and return */
    inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
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
