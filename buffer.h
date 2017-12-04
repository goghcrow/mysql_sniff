#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>    /*size_t*/
#include <sys/types.h> /*ssize_t*/

#define BufCheapPrepend 8

struct buffer;

#define buf_create(s) buf_create_ex((s), BufCheapPrepend)

struct buffer *buf_create_ex(size_t size, size_t prepend_size);
void buf_release(struct buffer *buf);

size_t buf_internalCapacity(struct buffer *buf);
size_t buf_readable(const struct buffer *buf);
size_t buf_writable(const struct buffer *buf);
size_t buf_prependable(const struct buffer *buf);

const char *buf_peek(const struct buffer *buf);
char *buf_beginWrite(struct buffer *buf);
void buf_has_written(struct buffer *buf, size_t len);
void buf_unwrite(struct buffer *buf, size_t len);

const char *buf_findStr(struct buffer *buf, char *str);
const char *buf_findChar(struct buffer *buf, char c);
const char *buf_findCRLF(struct buffer *buf);
const char *buf_findEOL(struct buffer *buf);

void buf_retrieveAsString(struct buffer *buf, size_t len, char *str);
void buf_retrieveAll(struct buffer *buf);
void buf_retrieve(struct buffer *buf, size_t len);
void buf_retrieveUntil(struct buffer *buf, const char *end);
void buf_retrieveInt64(struct buffer *buf);
void buf_retrieveInt32(struct buffer *buf);
void buf_retrieveInt16(struct buffer *buf);
void buf_retrieveInt8(struct buffer *buf);

void buf_ensureWritable(struct buffer *buf, size_t len);
void buf_append(struct buffer *buf, const char *data, size_t len);
void buf_prepend(struct buffer *buf, const char *data, size_t len);
void buf_shrink(struct buffer *buf, size_t reserve);

void buf_appendInt64(struct buffer *buf, int64_t x);
void buf_appendInt32(struct buffer *buf, int32_t x);
void buf_appendInt16(struct buffer *buf, int16_t x);
void buf_appendInt8(struct buffer *buf, int8_t x);

void buf_appendInt64LE(struct buffer *buf, int64_t x);
void buf_appendInt32LE(struct buffer *buf, int32_t x);
void buf_appendInt16LE(struct buffer *buf, int16_t x);

void buf_prependInt64(struct buffer *buf, int64_t x);
void buf_prependInt32(struct buffer *buf, int32_t x);
void buf_prependInt16(struct buffer *buf, int16_t x);
void buf_prependInt8(struct buffer *buf, int8_t x);

void buf_prependInt64LE(struct buffer *buf, int64_t x);
void buf_prependInt32LE(struct buffer *buf, int32_t x);
void buf_prependInt16LE(struct buffer *buf, int16_t x);

int64_t buf_peekInt64(const struct buffer *buf);
int32_t buf_peekInt32(const struct buffer *buf);
int16_t buf_peekInt16(const struct buffer *buf);
int8_t buf_peekInt8(const struct buffer *buf);

int64_t buf_peekInt64LE(const struct buffer *buf);
int32_t buf_peekInt32LE(const struct buffer *buf);
int32_t buf_peekInt32LE24(const struct buffer *buf);
int16_t buf_peekInt16LE(const struct buffer *buf);

int64_t buf_readInt64(struct buffer *buf);
int32_t buf_readInt32(struct buffer *buf);
int16_t buf_readInt16(struct buffer *buf);
int8_t buf_readInt8(struct buffer *buf);

int64_t buf_readInt64LE(struct buffer *buf);
int32_t buf_readInt32LE(struct buffer *buf);
int32_t buf_readInt32LE24(struct buffer *buf); // 供 mysql 协议使用的鬼畜 encode
int16_t buf_readInt16LE(struct buffer *buf);

char *buf_readCStr(struct buffer *buf, char *str, int sz);
char *buf_readStr(struct buffer *buf, char *str, int sz);
char* buf_dupCStr(struct buffer *buf);
char* buf_dupStr(struct buffer *buf, int sz);

ssize_t buf_readFd(struct buffer *buf, int fd, int *errno_);

// 顾名思义, 只读视图, 可嵌套创建
// 创建只读视图后, 被创建只读视图的 buffer 锁定, 只能读不能写
// 等到 所有从其创建的只读视图全部 Release 后恢复可写
// 缓存了一份应对 mysql 拆分 Tcp segment 频繁创建删除只读视图
struct buffer* buf_readonlyView(struct buffer *buf, int sz);
bool buf_writeLocked(struct buffer *buf);
bool buf_isReadonlyView(struct buffer *buf);

// 危险 api
size_t buf_getReadIndex(struct buffer *buf);
void buf_setReadIndex(struct buffer *buf, size_t read_idx);
size_t buf_getWriteIndex(struct buffer *buf);
void buf_setWriteIndex(struct buffer *buf, size_t write_idx);

#endif