#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/uio.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <assert.h>
#include "endian.h"
#include "buffer.h"

struct buffer
{
    size_t read_idx;
    size_t write_idx;
    size_t sz;
    size_t p_sz;
    char *buf;

    // 只读视图扩展字段
    size_t refcount;      // 当前视图创建的只读视图的引用计数
    struct buffer *src;   // 指向只读视图的源视图
    struct buffer *cache; // 缓存一份只读视图
};

#define ASSERT_WRITE(buf) assert(!buf_writeLocked(buf))

struct buffer *buf_create_ex(size_t size, size_t prepend_size)
{
    assert(size > 0);
    assert(prepend_size >= 0);

    size_t sz = size + prepend_size;
    struct buffer *buf = calloc(1, sizeof(*buf));
    if (buf == NULL)
    {
        return NULL;
    }
    buf->buf = calloc(1, sz);
    if (buf->buf == NULL)
    {
        free(buf);
        return NULL;
    }
    buf->sz = sz;
    buf->read_idx = prepend_size;
    buf->write_idx = prepend_size;
    buf->p_sz = prepend_size;
    buf->refcount = 0;
    buf->src = NULL;
    return buf;
}

void buf_release(struct buffer *buf)
{
    // 可以嵌套创建readonlyView, 都要检查 refcount
    assert(buf->refcount == 0);

    if (buf->src)
    {
        // 只读视图
        buf->src->refcount--;

        // 缓存 只读视图, 为 mysql 协议解析做的优化
        if (!buf->src->cache)
        {
            buf->src->cache = buf;
        }
        else
        {
            free(buf);
        }
    }
    else
    {
        // 常规 buffer
        free(buf->buf);
        if (buf->cache)
        {
            free(buf->cache);
        }
        free(buf);
    }
}

size_t buf_readable(const struct buffer *buf)
{
    return buf->write_idx - buf->read_idx;
}

size_t buf_writable(const struct buffer *buf)
{
    return buf->sz - buf->write_idx;
}

size_t buf_internalCapacity(struct buffer *buf)
{
    return buf->sz;
}

size_t buf_prependable(const struct buffer *buf)
{
    return buf->read_idx;
}

const char *buf_peek(const struct buffer *buf)
{
    return buf->buf + buf->read_idx;
}

char *buf_beginWrite(struct buffer *buf)
{
    return buf->buf + buf->write_idx;
}

void buf_has_written(struct buffer *buf, size_t len)
{
    assert(len <= buf_writable(buf));
    buf->write_idx += len;
}

void buf_unwrite(struct buffer *buf, size_t len)
{
    ASSERT_WRITE(buf);
    assert(len <= buf_readable(buf));
    buf->write_idx -= len;
}

const char *buf_findStr(struct buffer *buf, char *str)
{
    return (char *)memmem(buf_peek(buf), buf_readable(buf), str, strlen(str));
}

const char *buf_findChar(struct buffer *buf, char c)
{
    return (char *)memchr(buf_peek(buf), c, buf_readable(buf));
}

const char *buf_findCRLF(struct buffer *buf)
{
    return (char *)memmem(buf_peek(buf), buf_readable(buf), "\r\n", 2);
}

const char *buf_findEOL(struct buffer *buf)
{
    return (char *)memchr(buf_peek(buf), '\n', buf_readable(buf));
}

void buf_retrieveAsString(struct buffer *buf, size_t len, char *str)
{
    assert(str != NULL);
    memcpy(str, buf_peek(buf), len);
    str[len] = 0;
    buf_retrieve(buf, len);
}

void buf_retrieveAll(struct buffer *buf)
{
    buf->read_idx = buf->p_sz;
    buf->write_idx = buf->p_sz;
}

void buf_retrieve(struct buffer *buf, size_t len)
{
    assert(len <= buf_readable(buf));
    if (len < buf_readable(buf))
    {
        buf->read_idx += len;
    }
    else
    {
        buf_retrieveAll(buf);
    }
}

void buf_retrieveUntil(struct buffer *buf, const char *end)
{
    assert(buf_peek(buf) <= end);
    assert(end <= buf_beginWrite(buf));
    buf_retrieve(buf, end - buf_peek(buf));
}

void buf_retrieveInt64(struct buffer *buf)
{
    buf_retrieve(buf, sizeof(int64_t));
}

void buf_retrieveInt32(struct buffer *buf)
{
    buf_retrieve(buf, sizeof(int32_t));
}

void buf_retrieveInt16(struct buffer *buf)
{
    buf_retrieve(buf, sizeof(int16_t));
}

void buf_retrieveInt8(struct buffer *buf)
{
    buf_retrieve(buf, sizeof(int8_t));
}

static void buf_swap(struct buffer *buf, size_t nsz)
{
    // TODO nsz > buf->size realloc ?
    assert(nsz >= buf_readable(buf));
    void *nbuf = calloc(1, nsz);
    assert(nbuf);
    memcpy(nbuf + buf->p_sz, buf_peek(buf), buf_readable(buf));
    free(buf->buf);
    buf->buf = nbuf;
    buf->sz = nsz;
}

static void buf_makeSpace(struct buffer *buf, size_t len)
{
    size_t readable = buf_readable(buf);
    if (buf_prependable(buf) + buf_writable(buf) - buf->p_sz < len)
    {
        size_t nsz = buf->write_idx + len;
        buf_swap(buf, nsz);
    }
    else
    {
        assert(buf->p_sz < buf->read_idx);
        memmove(buf->buf + buf->p_sz, buf_peek(buf), readable);
    }

    buf->read_idx = buf->p_sz;
    buf->write_idx = buf->p_sz + readable;
    assert(readable == buf_readable(buf));
}

void buf_ensureWritable(struct buffer *buf, size_t len)
{
    ASSERT_WRITE(buf);
    if (buf_writable(buf) < len)
    {
        buf_makeSpace(buf, len);
    }
    assert(buf_writable(buf) >= len);
}

void buf_append(struct buffer *buf, const char *data, size_t len)
{
    ASSERT_WRITE(buf);
    buf_ensureWritable(buf, len);
    memcpy(buf_beginWrite(buf), data, len);
    buf_has_written(buf, len);
}

void buf_prepend(struct buffer *buf, const char *data, size_t len)
{
    assert(len <= buf_prependable(buf));
    buf->read_idx -= len;
    memcpy((void *)buf_peek(buf), data, len);
}

void buf_shrink(struct buffer *buf, size_t reserve)
{
    ASSERT_WRITE(buf);
    buf_swap(buf, buf->p_sz + buf_readable(buf) + reserve);
}

void buf_appendInt64(struct buffer *buf, int64_t x)
{
    int64_t be64 = htobe64(x);
    buf_append(buf, (char *)&be64, sizeof(int64_t));
}

void buf_appendInt32(struct buffer *buf, int32_t x)
{
    int32_t be32 = htobe32(x);
    buf_append(buf, (char *)&be32, sizeof(int32_t));
}

void buf_appendInt16(struct buffer *buf, int16_t x)
{
    int16_t be16 = htobe16(x);
    buf_append(buf, (char *)&be16, sizeof(int16_t));
}

void buf_appendInt8(struct buffer *buf, int8_t x)
{
    buf_append(buf, (char *)&x, sizeof(int8_t));
}

void buf_appendInt64LE(struct buffer *buf, int64_t x)
{
    int64_t le64 = htole64(x);
    buf_append(buf, (char *)&le64, sizeof(int64_t));
}

void buf_appendInt32LE(struct buffer *buf, int32_t x)
{
    int32_t le32 = htole32(x);
    buf_append(buf, (char *)&le32, sizeof(int32_t));
}

void buf_appendInt16LE(struct buffer *buf, int16_t x)
{
    int16_t le16 = htole16(x);
    buf_append(buf, (char *)&le16, sizeof(int16_t));
}

void buf_prependInt64(struct buffer *buf, int64_t x)
{
    int64_t be64 = htobe64(x);
    buf_prepend(buf, (char *)&be64, sizeof(int64_t));
}

void buf_prependInt32(struct buffer *buf, int32_t x)
{
    int32_t be32 = htobe32(x);
    buf_prepend(buf, (char *)&be32, sizeof(int32_t));
}

void buf_prependInt16(struct buffer *buf, int16_t x)
{
    int16_t be16 = htobe16(x);
    buf_prepend(buf, (char *)&be16, sizeof(int16_t));
}

void buf_prependInt8(struct buffer *buf, int8_t x)
{
    buf_prepend(buf, (char *)&x, sizeof(int8_t));
}

void buf_prependInt64LE(struct buffer *buf, int64_t x)
{
    int64_t le64 = htole64(x);
    buf_prepend(buf, (char *)&le64, sizeof(int64_t));
}

void buf_prependInt32LE(struct buffer *buf, int32_t x)
{
    int32_t le32 = htole32(x);
    buf_prepend(buf, (char *)&le32, sizeof(int32_t));
}

void buf_prependInt16LE(struct buffer *buf, int16_t x)
{
    int16_t le16 = htole16(x);
    buf_prepend(buf, (char *)&le16, sizeof(int16_t));
}

int64_t buf_peekInt64(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int64_t));
    int64_t be64 = 0;
    memcpy(&be64, buf_peek(buf), sizeof(int64_t));
    return be64toh(be64);
}

int32_t buf_peekInt32(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int32_t));
    int32_t be32 = 0;
    memcpy(&be32, buf_peek(buf), sizeof(int32_t));
    return be32toh(be32);
}

int16_t buf_peekInt16(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int16_t));
    int16_t be16 = 0;
    memcpy(&be16, buf_peek(buf), sizeof(int16_t));
    return be16toh(be16);
}

int8_t buf_peekInt8(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int8_t));
    return *buf_peek(buf);
}

int64_t buf_peekInt64LE(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int64_t));
    int64_t le64 = 0;
    memcpy(&le64, buf_peek(buf), sizeof(int64_t));
    return le64toh(le64);
}

int32_t buf_peekInt32LE(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int32_t));
    int32_t le32 = 0;
    memcpy(&le32, buf_peek(buf), sizeof(int32_t));
    return le32toh(le32);
}

int32_t buf_peekInt32LE24(const struct buffer *buf)
{
    assert(buf_readable(buf) >= 3);
    int32_t le32 = 0x00000000; /* 0x000000{00 小端高位未使用} */
    memcpy(&le32, buf_peek(buf), 3);
    return le32toh(le32);
}

int16_t buf_peekInt16LE(const struct buffer *buf)
{
    assert(buf_readable(buf) >= sizeof(int16_t));
    int16_t le16 = 0;
    memcpy(&le16, buf_peek(buf), sizeof(int16_t));
    return le16toh(le16);
}

int64_t buf_readInt64(struct buffer *buf)
{
    int64_t x = buf_peekInt64(buf);
    buf_retrieveInt64(buf);
    return x;
}

int32_t buf_readInt32(struct buffer *buf)
{
    int32_t x = buf_peekInt32(buf);
    buf_retrieveInt32(buf);
    return x;
}

int16_t buf_readInt16(struct buffer *buf)
{
    int16_t x = buf_peekInt16(buf);
    buf_retrieveInt16(buf);
    return x;
}

int8_t buf_readInt8(struct buffer *buf)
{
    int8_t x = buf_peekInt8(buf);
    buf_retrieveInt8(buf);
    return x;
}

int64_t buf_readInt64LE(struct buffer *buf)
{
    int64_t x = buf_peekInt64LE(buf);
    buf_retrieveInt64(buf);
    return x;
}

int32_t buf_readInt32LE(struct buffer *buf)
{
    int32_t x = buf_peekInt32LE(buf);
    buf_retrieveInt32(buf);
    return x;
}

int32_t buf_readInt32LE24(struct buffer *buf)
{
    int32_t x = buf_peekInt32LE24(buf);
    buf_retrieve(buf, 3);
    return x;
}

int16_t buf_readInt16LE(struct buffer *buf)
{
    int16_t x = buf_peekInt16LE(buf);
    buf_retrieveInt16(buf);
    return x;
}

char *buf_readCStr(struct buffer *buf, char *str, int sz)
{
    int sz1;
    const char *eos = buf_findChar(buf, '\0');

    if (eos == NULL)
    {
        sz1 = buf_readable(buf) + 1;
    }
    else
    {
        sz1 = eos - buf_peek(buf) + 1;
    }

    if (sz < sz1)
    {
        return NULL;
    }

    memcpy(str, buf_peek(buf), sz);
    if (eos == NULL)
    {
        buf_retrieve(buf, sz1 - 1);
    }
    else
    {
        buf_retrieve(buf, sz1);
    }
    return str;
}

char *buf_readStr(struct buffer *buf, char *str, int sz)
{
    if (buf_readable(buf) < sz)
    {
        sz = buf_readable(buf);
    }

    memcpy(str, buf_peek(buf), sz);
    str[sz] = '\0';

    buf_retrieve(buf, sz);
    return str;
}

char *buf_dupCStr(struct buffer *buf)
{
    int sz;
    const char *eos = buf_findChar(buf, '\0');

    if (eos == NULL)
    {
        sz = buf_readable(buf) + 1;
    }
    else
    {
        sz = eos - buf_peek(buf) + 1;
    }

    char *str = calloc(sz, 1);
    if (str == NULL)
    {
        return NULL;
    }

    memcpy(str, buf_peek(buf), sz);
    if (eos == NULL)
    {
        buf_retrieve(buf, sz - 1);
    }
    else
    {
        buf_retrieve(buf, sz);
    }
    return str;
}

char *buf_dupStr(struct buffer *buf, int sz)
{
    if (buf_readable(buf) < sz)
    {
        sz = buf_readable(buf);
    }
    char *str = malloc(sz + 1);
    if (str == NULL)
    {
        return NULL;
    }

    memcpy(str, buf_peek(buf), sz);
    str[sz] = '\0';

    buf_retrieve(buf, sz);
    return str;
}

ssize_t buf_readFd(struct buffer *buf, int fd, int *errno_)
{
    ASSERT_WRITE(buf);
    char extrabuf[65535];
    struct iovec vec[2];
    size_t writable = buf_writable(buf);
    vec[0].iov_base = buf_beginWrite(buf);
    vec[0].iov_len = writable;
    vec[1].iov_base = extrabuf;
    vec[1].iov_len = sizeof(extrabuf);

    int iovcnt = writable < sizeof(extrabuf) ? 2 : 1;
    ssize_t n = readv(fd, vec, iovcnt);
    if (n < 0)
    {
        *errno_ = n;
    }
    else if (n <= writable)
    {
        buf->write_idx += n;
    }
    else
    {
        buf->write_idx = buf->sz;
        buf_append(buf, (char *)(&extrabuf[0]), n - writable);
    }

    return n;
}

bool buf_writeLocked(struct buffer *buf)
{
    return buf_isReadonlyView(buf) || buf->refcount > 0;
}

bool buf_isReadonlyView(struct buffer *buf)
{
    return buf->src != NULL;
}

struct buffer *buf_readonlyView(struct buffer *buf, int sz)
{
    assert(sz > 0);
    if (sz > buf_readable(buf))
    {
        sz = buf_readable(buf);
    }

    struct buffer *rbuf;

    if (buf->cache)
    {
        memset(buf->cache, 0, sizeof(*(buf->cache)));
        rbuf = buf->cache;
        buf->cache = NULL;
    }
    else
    {
        rbuf = calloc(1, sizeof(*buf));
        if (rbuf == NULL)
        {
            return NULL;
        }
    }

    rbuf->buf = buf->buf + buf->read_idx; // buf_peek(buf)
    rbuf->sz = sz;
    rbuf->read_idx = 0;
    rbuf->write_idx = sz;
    rbuf->p_sz = 0;
    rbuf->refcount = 0;
    rbuf->src = buf;
    buf->refcount++;
    return rbuf;
}

size_t buf_getReadIndex(struct buffer *buf)
{
    return buf->read_idx;
}

void buf_setReadIndex(struct buffer *buf, size_t read_idx)
{
    // assert(read_idx > 0 && read_idx <= buf->write_idx);
    buf->read_idx = read_idx;
}

size_t buf_getWriteIndex(struct buffer *buf)
{
    return buf->write_idx;
}

void buf_setWriteIndex(struct buffer *buf, size_t write_idx)
{
    ASSERT_WRITE(buf);
    assert(write_idx >= buf->read_idx && write_idx < buf->sz);
    buf->write_idx = write_idx;
}