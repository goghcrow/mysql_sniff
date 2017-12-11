#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif /* strsep */
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h> /*getopt*/
#include <ctype.h>  /*isspace*/

#include "mysql_sniff.h"
#include "tcpsniff.h"
#include "buffer.h"
#include "khash.h"

/*
TODO:

日志级别处理
- FIX 5.7 EOF 问题 conn_data->num_fields = conn_data->stmt_num_params;
- 处理 mysql 5.7 协议变更, 无 EOF packet
- 5.7 新协议 有问题 SET NAMES utf8 返回 解析有问题,, 状态不对...读到 ResultSet 了
- 加大量 文字注释: http://hutaow.com/blog/2013/11/06/mysql-protocol-analysis/
- 打印 Server 和 Client 的能力
- 支持 统计 sql 执行时间
- sannitizer 测试


OK: 支持多mysql端口
OK: 测试 新旧 两种协议 同时连接的场景
用简单的 strmap 处理 ResultSet 结果集?!  string <=> string
*/

/* thanks for https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-mysql.c */
#if !defined(UNUSED)
#define UNUSED(x) ((void)(x))
#endif

#define LOG_INFO(fmt, ...) \
    fprintf(stderr, "\x1B[1;32m" fmt "\x1B[0m\n", ##__VA_ARGS__);

#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "\x1B[1;31m" fmt "\x1B[0m\n", ##__VA_ARGS__);

#define PANIC(fmt, ...)                                                                                              \
    fprintf(stderr, "\x1B[1;31m" fmt "\x1B[0m in function %s %s:%d\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__); \
    exit(1);

/*
这里采用端口识别是否是 Mysql Server
Mysql Server 监听的端口正常情况下 与连接自动分配的端口一般不重合
如果 Mysql Client bind 的端口 与 某个 Mysql Server 监听的端口一致
会导致识别错误
fixme: 使用 ip 做校验
*/

// #define BUFDZ MYSQL_MAX_PACKET_LEN
#define BUFSZ 1024 * 1024
static char g_buf[BUFSZ]; /* 临时缓存 */

#define SESSION_BK_SZ 2 << 9
#define SESSION_BK_IDX(x) ((x) & ((2 << 9) - 1))
#define SESSION_BUFFER_SZ 8192 /* 每个 half connection 的默认接受缓存大小 */

// TODO 移除 kthash 依赖
// 声明需要存储 stmts 的 hashtable 类型 Map<INT64, struct mysql_stmt_data *>
KHASH_MAP_INIT_INT64(stmts, struct mysql_stmt_data *);

typedef struct mysql_conn_data mysql_conn_data_t;

struct tuple4
{
    uint32_t serv_ip;
    uint32_t cli_ip;
    uint16_t serv_port;
    uint16_t cli_port;
};

// mysql client <-> mysql server 会话
struct mysql_session
{
    struct tuple4 t4;
    mysql_conn_data_t *conn_data;
    struct buffer *cli_buf;
    struct buffer *serv_buf;
    struct mysql_session *next;
};

struct mysql_server
{
    uint16_t port;
    struct mysql_session *bk[SESSION_BK_SZ]; // idx: cli_port % SESSION_BK_SZ
};

/* mysql session store */
struct mysql_ss
{
    int sz;                       // 固定大小
    uint16_t serv_ports[10];      // 最多监听10个 mysql server 端口
    struct mysql_server *serv[0]; // 不占空间
};

struct mysql_stmt_data
{
    uint16_t nparam;
    uint8_t *param_flags;
};

// 按字段类型解析 dissect 预编译语句执行时绑定的值
typedef struct mysql_exec_dissector
{
    uint8_t type;
    uint8_t unsigned_flag;
    void (*dissector)(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
} mysql_exec_dissector_t;

// 会话状态
struct mysql_conn_data
{
    uint16_t srv_caps;
    uint16_t srv_caps_ext;
    uint16_t clnt_caps;
    uint16_t clnt_caps_ext;
    mysql_state_t state;
    uint16_t stmt_num_params;
    uint16_t stmt_num_fields;
    khash_t(stmts) * stmts;
    uint32_t frame_start_ssl;
    uint32_t frame_start_compressed;
    uint8_t compressed_state;

    // 扩展字段
    uint64_t num_fields; // FIX Mysql 5.7 协议ResultSet 废弃 EOF Packet 的问题
    uint64_t cur_field;
    char *user;
};

static uint64_t buf_readFle(struct buffer *buf, uint64_t *len, uint8_t *is_null);
static int buf_peekFleLen(struct buffer *buf);
static int buf_dupFleStr(struct buffer *buf, char **str);
bool mysql_is_completed_pdu(struct buffer *buf);
static struct mysql_stmt_data *mysql_stmt_data_create(uint16_t nparam);
static void mysql_stmt_data_release(struct mysql_stmt_data *stmt_data);
static void mysql_dissect_auth_switch_request(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_auth_switch_response(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_error_packet(struct buffer *buf);
static void mysql_set_conn_state(mysql_conn_data_t *conn_data, mysql_state_t state);
static void mysql_dissect_greeting(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_login(struct buffer *buf, mysql_conn_data_t *conn_data);
static int mysql_dissect_attributes(struct buffer *buf);
static void mysql_dissect_request(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_response(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_result_header(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_ok_packet(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_dissect_field_packet(struct buffer *buf, mysql_conn_data_t *conn_data);
static int mysql_dissect_session_tracker_entry(struct buffer *buf);
static void mysql_dissect_row_packet(struct buffer *buf);
static void mysql_dissect_exec_string(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_time(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_datetime(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_tiny(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_short(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_long(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_float(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_double(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_longlong(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static void mysql_dissect_exec_null(struct buffer *buf, uint8_t param_unsigned, int *param_idx);
static char mysql_dissect_exec_param(struct buffer *buf, int *param_idx, uint8_t param_flags);
static void mysql_dissect_response_prepare(struct buffer *buf, mysql_conn_data_t *conn_data);
static void mysql_print_bytes(const char *payload, size_t size);

static void mysql_print_bytes(const char *payload, size_t size)
{
    const char *tmp_ptr = payload;
    int byte_cnt = 0;
    while (byte_cnt++ < size)
    {
        printf("%c", *tmp_ptr);
        tmp_ptr++;
    }
    printf("\n");
}

static struct mysql_conn_data *
mysql_conn_data_create()
{
    struct mysql_conn_data *d = calloc(1, sizeof(*d));
    if (d == NULL)
    {
        return NULL;
    }

    d->srv_caps = 0;
    d->clnt_caps = 0;
    d->clnt_caps_ext = 0;
    d->state = UNDEFINED;
    d->stmts = kh_init(stmts);
    d->frame_start_ssl = 0;
    d->frame_start_compressed = 0;
    d->compressed_state = MYSQL_COMPRESS_NONE;
    d->num_fields = 0;
    d->cur_field = 0;

    return d;
}

static void
mysql_conn_data_release(struct mysql_conn_data *d)
{
    if (d->user)
    {
        free(d->user);
    }

    // 释放保存的所有事务元信息
    struct mysql_stmt_data *stmt_data;
    khint_t k;
    for (k = kh_begin(d->stmts); k != kh_end(d->stmts); ++k)
    {
        if (kh_exist(d->stmts, k))
        {
            stmt_data = kh_value(d->stmts, k);
            mysql_stmt_data_release(stmt_data);
        }
    }

    kh_destroy(stmts, d->stmts);
    free(d);
}

static struct mysql_session *
mysql_session_create(struct tuple4 *t4)
{
    struct mysql_session *s = calloc(1, sizeof(*s));
    if (s == NULL)
    {
        return s;
    }
    s->conn_data = mysql_conn_data_create();
    if (s->conn_data == NULL)
    {
        free(s);
        return NULL;
    }
    s->cli_buf = buf_create(SESSION_BUFFER_SZ);
    if (s->cli_buf == NULL)
    {
        mysql_conn_data_release(s->conn_data);
        free(s);
        return NULL;
    }
    s->serv_buf = buf_create(SESSION_BUFFER_SZ);
    if (s->serv_buf == NULL)
    {
        buf_release(s->cli_buf);
        mysql_conn_data_release(s->conn_data);
        free(s);
        return NULL;
    }

    s->t4.cli_ip = t4->cli_ip;
    s->t4.cli_port = t4->cli_port;
    s->t4.serv_ip = t4->serv_ip;
    s->t4.serv_port = t4->serv_port;
    return s;
}

static void
mysql_session_release(struct mysql_session *s)
{
    buf_release(s->cli_buf);
    buf_release(s->serv_buf);
    mysql_conn_data_release(s->conn_data);
    free(s);
}

static struct mysql_ss *
mysql_ss_create(uint16_t serv_ports[], int sz)
{
    int i;
    struct mysql_ss *ss = calloc(1, sizeof(*ss) + sz * sizeof(struct mysql_server));
    if (ss == NULL)
    {
        return NULL;
    }
    ss->sz = sz;
    for (i = 0; i < sz; i++)
    {
        ss->serv_ports[i] = serv_ports[i];
        ss->serv[i] = calloc(1, sizeof(struct mysql_server));
        assert(ss->serv[i]);
    }
    return ss;
}

static void
mysql_ss_release(struct mysql_ss *ss)
{
    int i, j;
    struct mysql_session *head, *tmp;
    for (i = 0; i < ss->sz; i++)
    {
        if (ss->serv[i])
        {
            for (j = 0; j < SESSION_BK_SZ; j++)
            {
                head = ss->serv[i]->bk[j];
                while (head)
                {
                    tmp = head->next;
                    mysql_session_release(head);
                    head = tmp;
                }
                ss->serv[i]->bk[j] = NULL;
            }
            free(ss->serv[i]);
        }
    }
    free(ss);
}

static bool
mysql_is_server(struct mysql_ss *ss, uint16_t port)
{
    int i;
    for (i = 0; i < ss->sz; i++)
    {
        if (ss->serv_ports[i] == port)
        {
            return true;
        }
    }
    return false;
}

static void
mysql_fix_tuple4(struct mysql_ss *ss, struct tuple4 *t4)
{
    if (mysql_is_server(ss, t4->serv_port))
    {
        return;
    }
    else if (mysql_is_server(ss, t4->cli_port))
    {
        uint32_t tmp;

        tmp = t4->serv_port;
        t4->serv_port = t4->cli_port;
        t4->cli_port = tmp;

        tmp = t4->serv_ip;
        t4->serv_ip = t4->cli_ip;
        t4->cli_ip = tmp;
    }
    else
    {
        PANIC("接收到无法识别的数据包, 来自端口 sport=%u dport=%u, 请确认监听 Mysql Server 端口", t4->serv_port, t4->cli_port);
    }
}

// private
static struct mysql_session *
mysql_ss_get_internal(struct mysql_ss *ss, struct tuple4 *t4, bool remove)
{
    int i;
    struct mysql_session *head, *last = NULL;
    for (i = 0; i < ss->sz; i++)
    {
        if (ss->serv_ports[i] == t4->serv_port)
        {
            int idx = SESSION_BK_IDX(t4->cli_port);
            head = ss->serv[i]->bk[idx];
            while (head)
            {
                if (head->t4.cli_ip == t4->cli_ip)
                {
                    if (remove)
                    {
                        if (last == NULL)
                        {
                            ss->serv[i]->bk[idx] = head->next;
                        }
                        else
                        {
                            last->next = head->next;
                        }
                        mysql_session_release(head);
                        head = NULL;
                    }
                    return head;
                }
                last = head;
                head = head->next;
            }
        }
    }
    return NULL;
}

// private
// 创建新的mysql_session, 需要自行保证之前不存在
static struct mysql_session *
mysql_ss_add_internal(struct mysql_ss *ss, struct tuple4 *t4)
{
    int i;
    struct mysql_session *new;
    for (i = 0; i < ss->sz; i++)
    {
        if (ss->serv_ports[i] == t4->serv_port)
        {
            int idx = SESSION_BK_IDX(t4->cli_port);
            new = mysql_session_create(t4);
            if (new == NULL)
            {
                assert(false);
            }
            new->next = ss->serv[i]->bk[idx];
            ss->serv[i]->bk[idx] = new;
            return new;
        }
    }
    assert(false);
    return NULL;
}

static struct mysql_session *
mysql_ss_get(struct mysql_ss *ss, struct tuple4 *t4)
{
    mysql_fix_tuple4(ss, t4);
    struct mysql_session *s = mysql_ss_get_internal(ss, t4, false);
    if (s == NULL)
    {
        return mysql_ss_add_internal(ss, t4);
    }
    else
    {
        return s;
    }
}

static void
mysql_ss_del(struct mysql_ss *ss, struct tuple4 *t4)
{
    mysql_fix_tuple4(ss, t4);
    mysql_ss_get_internal(ss, t4, true);
}

static void
mysql_tuple4_init(struct tuple4 *t4, uint32_t s_ip, uint16_t s_port, uint32_t d_ip, uint16_t d_port)
{
    t4->serv_ip = s_ip;
    t4->cli_ip = d_ip;
    t4->serv_port = s_port;
    t4->cli_port = d_port;
}

static struct buffer *
mysql_session_getbuf(struct mysql_session *s, struct tuple4 *t4, uint16_t s_port, bool *is_response)
{
    if (t4->serv_port == s_port)
    {
        *is_response = true;
        return s->serv_buf;
    }
    else
    {
        *is_response = false;
        return s->cli_buf;
    }
}

// TODO 测试 nparam = 0
static struct mysql_stmt_data *
mysql_stmt_data_create(uint16_t nparam)
{
    struct mysql_stmt_data *stmt_data = calloc(1, sizeof(*stmt_data));
    if (stmt_data == NULL)
    {
        return NULL;
    }
    stmt_data->nparam = nparam;

    if (nparam)
    {
        int flagsize = (int)(sizeof(uint8_t) * nparam);
        stmt_data->param_flags = (uint8_t *)malloc(flagsize);
        if (stmt_data->param_flags == NULL)
        {
            free(stmt_data);
            return NULL;
        }
        memset(stmt_data->param_flags, 0, flagsize);
    }
    return stmt_data;
}

static void
mysql_stmt_data_release(struct mysql_stmt_data *stmt_data)
{
    if (stmt_data->param_flags)
    {
        free(stmt_data->param_flags);
    }
    free(stmt_data);
}

bool mysql_is_completed_pdu(struct buffer *buf)
{
    int total_sz = buf_readable(buf);
    if (total_sz < 4) /* regular header 3+1 (len+id) */
    {
        return false;
    }

    int32_t pkt_sz = buf_peekInt32LE24(buf);
    if (pkt_sz <= 0 || pkt_sz >= MYSQL_MAX_PACKET_LEN)
    {
        PANIC("Malformed Mysql Packet (size=%d)\n", pkt_sz);
        return false;
    }

    // TODO ?
    if ((total_sz - pkt_sz) == 7)
    {
        return total_sz >= pkt_sz + 7; /* compressed header 3+1+3 (len+id+cmp_len) */
    }
    else
    {
        return total_sz >= pkt_sz + 4; /* regular header 3+1 (len+id) */
    }
}

/**
Value Of     # Of Bytes  Description
First Byte   Following
----------   ----------- -----------
0-250        0           = value of first byte
251          0           column value = NULL
only appropriate in a Row Data Packet
252          2           = value of following 16-bit word
253          3           = value of following 24-bit word
254          8           = value of following 64-bit word
*/
// One may ask why the 1 byte length is limited to 251, when the first reserved value in the
// net_store_length( ) is 252. The code 251 has a special meaning. It indicates that there is
// no length value or data following the code, and the value of the field is the SQL

// field length encoded
// len     out
// is_null out   where to store ISNULL flag, may be NULL
// return where to store FLE value, may be NULL
static uint64_t
buf_readFle(struct buffer *buf, uint64_t *len, uint8_t *is_null)
{
    uint8_t prefix = buf_readInt8(buf);

    if (is_null)
    {
        *is_null = 0;
    }

    switch (prefix)
    {
    case 251:
        if (len)
        {
            *len = 1;
        }
        if (is_null)
        {
            *is_null = 1;
        }
        return 0;
    case 252:
        if (len)
        {
            *len = 1 + 2;
        }
        return buf_readInt16LE(buf);
    case 253:
        if (len)
        {
            *len = 1 + 4;
        }
        return buf_readInt32LE(buf);

        // TODO 好像有种情况是这样 !!!
        /*
		if (len) {
			*len = 1 + 3;
		}
		return buf_readInt32LE24(buf);
		*/
    case 254:
        if (len)
        {
            *len = 1 + 8;
        }
        return buf_readInt64LE(buf);
    default: /* < 251 */
        if (len)
        {
            *len = 1;
        }
        return prefix;
    }
}

static int
buf_peekFleLen(struct buffer *buf)
{
    uint8_t prefix = buf_readInt8(buf);

    switch (prefix)
    {
    case 251:
        return 1;
    case 252:
        return 1 + 2;
    case 253:
        return 1 + 4;
        // TODO
        return 1 + 3;
    case 254:
        return 1 + 8;
    default: /* < 251 */
        return 1;
    }
}

static int
buf_dupFleStr(struct buffer *buf, char **str)
{
    uint64_t len;
    uint64_t sz = buf_readFle(buf, &len, NULL);
    *str = buf_dupStr(buf, sz);
    return len + sz;
}

static int
buf_readFleStr(struct buffer *buf, char *str, int sz)
{
    uint64_t len;
    uint64_t sz1 = buf_readFle(buf, &len, NULL);
    if (sz1 > sz)
    {
        assert(false);
        return -1;
    }

    buf_readStr(buf, str, sz1);
    return len + sz1;
}

/*
https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
https://dev.mysql.com/doc/internals/en/client-server-protocol.html

Server Status: 0x0002
.... .... .... ...0 = In transaction: Not set
.... .... .... ..1. = AUTO_COMMIT: Set
.... .... .... .0.. = More results: Not set
.... .... .... 0... = Multi query - more resultsets: Not set
.... .... ...0 .... = Bad index used: Not set
.... .... ..0. .... = No index used: Not set
.... .... .0.. .... = Cursor exists: Not set
.... .... 0... .... = Last row sent: Not set
.... ...0 .... .... = database dropped: Not set
.... ..0. .... .... = No backslash escapes: Not set
.... .0.. .... .... = Session state changed: Not set
.... 0... .... .... = Query was slow: Not set
...0 .... .... .... = PS Out Params: Not set


Server Capabilities: 0xffff
.... .... .... ...1 = Long Password: Set
.... .... .... ..1. = Found Rows: Set
.... .... .... .1.. = Long Column Flags: Set
.... .... .... 1... = Connect With Database: Set
.... .... ...1 .... = Don't Allow database.table.column: Set
.... .... ..1. .... = Can use compression protocol: Set
.... .... .1.. .... = ODBC Client: Set
.... .... 1... .... = Can Use LOAD DATA LOCAL: Set
.... ...1 .... .... = Ignore Spaces before '(': Set
.... ..1. .... .... = Speaks 4.1 protocol (new flag): Set
.... .1.. .... .... = Interactive Client: Set
.... 1... .... .... = Switch to SSL after handshake: Set
...1 .... .... .... = Ignore sigpipes: Set
..1. .... .... .... = Knows about transactions: Set
.1.. .... .... .... = Speaks 4.1 protocol (old flag): Set
1... .... .... .... = Can do 4.1 authentication: Set

Extended Server Capabilities: 0xc1ff
.... .... .... ...1 = Multiple statements: Set
.... .... .... ..1. = Multiple results: Set
.... .... .... .1.. = PS Multiple results: Set
.... .... .... 1... = Plugin Auth: Set
.... .... ...1 .... = Connect attrs: Set
.... .... ..1. .... = Plugin Auth LENENC Client Data: Set
.... .... .1.. .... = Client can handle expired passwords: Set
.... .... 1... .... = Session variable tracking: Set
.... ...1 .... .... = Deprecate EOF: Set
1100 000. .... .... = Unused: 0x60

Client Capabilities: 0x8208
.... .... .... ...0 = Long Password: Not set
.... .... .... ..0. = Found Rows: Not set
.... .... .... .0.. = Long Column Flags: Not set
.... .... .... 1... = Connect With Database: Set
.... .... ...0 .... = Don't Allow database.table.column: Not set
.... .... ..0. .... = Can use compression protocol: Not set
.... .... .0.. .... = ODBC Client: Not set
.... .... 0... .... = Can Use LOAD DATA LOCAL: Not set
.... ...0 .... .... = Ignore Spaces before '(': Not set
.... ..1. .... .... = Speaks 4.1 protocol (new flag): Set
.... .0.. .... .... = Interactive Client: Not set
.... 0... .... .... = Switch to SSL after handshake: Not set
...0 .... .... .... = Ignore sigpipes: Not set
..0. .... .... .... = Knows about transactions: Not set
.0.. .... .... .... = Speaks 4.1 protocol (old flag): Not set
1... .... .... .... = Can do 4.1 authentication: Set

Extended Client Capabilities: 0x0008
.... .... .... ...0 = Multiple statements: Not set
.... .... .... ..0. = Multiple results: Not set
.... .... .... .0.. = PS Multiple results: Not set
.... .... .... 1... = Plugin Auth: Set
.... .... ...0 .... = Connect attrs: Not set
.... .... ..0. .... = Plugin Auth LENENC Client Data: Not set
.... .... .0.. .... = Client can handle expired passwords: Not set
.... .... 0... .... = Session variable tracking: Not set
.... ...0 .... .... = Deprecate EOF: Not set
0000 000. .... .... = Unused: 0x00


example:

Uint8 						0x0a		Protocol
NULL-terminated-str 					Banner
uint32LE								ThreadId
NULL-terminated-str						Salt 用于客户端加密密码
UInt16LE					0xffff		Server Capabilities
UInt8LE						33			Server Language, Charset, 33: utf8 COLLATE utf8_general_ci
UInt16LE					0x0002		Server Status, 0x0002 status autommit
UInt16LE					0x0008		Extended Server Capalibities
Uint8						21			Authentication Plugin Length, 21 = strlen(mysql_native_password)
10bytes						Unused		str_repeat("\0", 10)
NULL-terminated-str			具体盐值	 salt		
NULL-terminated-str			"mysql_native_password\0"	Authentication Plugin
*/
static void
mysql_dissect_greeting(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    LOG_INFO("Server Greeting");
    int protocol = buf_readInt8(buf);
    if (protocol == 0xff)
    {
        mysql_dissect_error_packet(buf);
        return;
    }

    mysql_set_conn_state(conn_data, LOGIN);
    LOG_INFO("Protocol 0x%02x", protocol);

    // null 结尾字符串, Banner
    buf_readCStr(buf, g_buf, BUFSZ);
    LOG_INFO("Server Version: %s", g_buf);

    /* 4 bytes little endian thread_id */
    int thread_id = buf_readInt32LE(buf);
    LOG_INFO("Server Thread Id %d", thread_id);

    /* salt string */
    buf_readCStr(buf, g_buf, BUFSZ);
    // LOG_INFO("Salt %s", g_buf);

    /* rest is optional */
    if (!buf_readable(buf))
    {
        return;
    }

    /* 2 bytes CAPS */
    conn_data->srv_caps = buf_readInt16LE(buf);
    char* tofree = mysql_get_cap_val(conn_data->srv_caps, "未知");
    LOG_INFO("Server Capabilities %s (0x%04x)", tofree, conn_data->srv_caps);
    free(tofree);

    /* rest is optional */
    if (!buf_readable(buf))
    {
        return;
    }

    /* 1 byte Charset */
    int8_t charset = buf_readInt8(buf);
    LOG_INFO("Server Language [%s](0x%02x)", mysql_get_charset(charset, "未知编码"), charset);

    /* 2 byte ServerStatus */
    int16_t server_status = buf_readInt16LE(buf);
    tofree = mysql_get_server_status_val(server_status, "未知");
    LOG_INFO("Server Statue %s (0x%04x)", tofree, server_status);
    free(tofree);

    /* 2 bytes ExtCAPS */
    conn_data->srv_caps_ext = buf_readInt16LE(buf);
    tofree = mysql_get_ext_cap_val(conn_data->srv_caps_ext, "未知");
    LOG_INFO("Server Extended Capabilities %s (0x%04x)", tofree, conn_data->srv_caps_ext);
    free(tofree);

    /* 1 byte Auth Plugin Length */
    int8_t auto_plugin_len = buf_readInt8(buf);
    UNUSED(auto_plugin_len);

    /* 10 bytes unused */
    buf_retrieve(buf, 10);

    /* 4.1+ server: rest of salt */
    if (buf_readable(buf))
    {
        buf_readCStr(buf, g_buf, BUFSZ);
        // LOG_INFO("Server Rest Salt %s", g_buf);
    }

    /* 5.x server: auth plugin */
    if (buf_readable(buf))
    {
        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Server Auth Plugin: %s", g_buf);
    }
}

static void
mysql_dissect_error_packet(struct buffer *buf)
{
    int16_t errno = buf_readInt16LE(buf);
    LOG_ERROR("Error Code %d", errno);

    const char *c = buf_peek(buf);
    if (*c == '#')
    {
        buf_retrieve(buf, 1);
        buf_readStr(buf, g_buf, 5);
        LOG_ERROR("SQL State %s", g_buf);
    }
    buf_readStr(buf, g_buf, BUFSZ);
    LOG_ERROR("Error Message: %s", g_buf);
}

static void
mysql_set_conn_state(mysql_conn_data_t *conn_data, mysql_state_t state)
{
    conn_data->state = state;
}

static void
mysql_dissect_login(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    LOG_INFO("Login Request");

    /* after login there can be OK or DENIED */
    mysql_set_conn_state(conn_data, RESPONSE_OK);

    /*
UInt16LE				Client Capabilities
UInt16LE				Extended Client Capabilities
UInt32LE				MAX Packet: e.g. 300
UInt8					Charset: utf8 COLLATE utf8_general_ci (33)
Unused		 			23 Bytes 0x00
NullTerminatedString	Username: e.g. root
UInt8LenString			Password: e.g. 71f31c52cab00272caa32423f1714464113b7819
NullTerminatedString	Schema: e.g. test DB
NullTerminatedString	Client Auth Plugin: e.g. mysql_native_password
					* connection attributes
*/

    conn_data->clnt_caps = buf_readInt16LE(buf);
    char *tofree = mysql_get_cap_val(conn_data->clnt_caps, "未知");
    LOG_INFO("Client Capabilities %s (0x%04x)", tofree, conn_data->clnt_caps);
    free(tofree);

    /* Next packet will be use SSL */
    if (!(conn_data->frame_start_ssl) && conn_data->clnt_caps & MYSQL_CAPS_SL)
    {
        LOG_INFO("Response: SSL Handshake");
        conn_data->frame_start_ssl = 1;
        PANIC("不支持 SSL Mysql 协议");
    }

    uint32_t maxpkt;
    uint8_t charset;
    /* 4.1 protocol */
    if (conn_data->clnt_caps & MYSQL_CAPS_CU)
    {
        /* 2 bytes client caps */
        conn_data->clnt_caps_ext = buf_readInt16LE(buf);
        char *tofree = mysql_get_ext_cap_val(conn_data->clnt_caps_ext, "未知");
        LOG_INFO("Client Extended Capabilities %s (0x%04x)", tofree, conn_data->clnt_caps_ext);
        free(tofree);

        /* 4 bytes max package */
        maxpkt = buf_readInt32LE(buf);
        LOG_INFO("Client MAX Packet %d", maxpkt);

        /* 1 byte Charset */
        charset = buf_readInt8(buf);
        LOG_INFO("Client Charset [%s](0x%02x)", mysql_get_charset(charset, "未知编码"), charset);

        /* filler 23 bytes */
        buf_retrieve(buf, 23);
    }
    else
    { /* pre-4.1 */
        /* 3 bytes max package */
        maxpkt = buf_readInt32LE24(buf);
        LOG_INFO("Client MAX Packet %d", maxpkt);
    }

    /* User name */
    buf_readCStr(buf, g_buf, BUFSZ);
    LOG_INFO("Client User %s", g_buf);
    conn_data->user = strdup(g_buf);

    /* rest is optional */
    if (!buf_readable(buf))
    {
        return;
    }

    /* 两种情况: password: ascii or length+ascii */
    if (conn_data->clnt_caps & MYSQL_CAPS_SC)
    {
        uint8_t lenstr = buf_readInt8(buf);
        buf_readStr(buf, g_buf, lenstr);
    }
    else
    {
        buf_readCStr(buf, g_buf, BUFSZ);
    }
    LOG_INFO("Client Password:");
    mysql_print_bytes(g_buf, strlen(g_buf));

    if (!buf_readable(buf))
    {
        return;
    }

    /* optional: initial schema */
    if (conn_data->clnt_caps & MYSQL_CAPS_CD)
    {
        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Client Schema %s", g_buf);
    }

    /* optional: authentication plugin */
    if (conn_data->clnt_caps_ext & MYSQL_CAPS_PA)
    {
        mysql_set_conn_state(conn_data, AUTH_SWITCH_REQUEST);

        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Client Auth Plugin %s", g_buf);
    }

    /* optional: connection attributes */
    if (conn_data->clnt_caps_ext & MYSQL_CAPS_CA && buf_readable(buf))
    {
        uint64_t connattrs_length = buf_readFle(buf, NULL, NULL);
        while (connattrs_length > 0)
        {
            int length = mysql_dissect_attributes(buf);
            connattrs_length -= length;
        }
    }
}

static int
mysql_dissect_attributes(struct buffer *buf)
{
    char *mysql_connattrs_name = NULL;
    char *mysql_connattrs_value = NULL;

    int name_len = buf_dupFleStr(buf, &mysql_connattrs_name);
    int val_len = buf_dupFleStr(buf, &mysql_connattrs_value);
    LOG_INFO("Client Attributes %s %s", mysql_connattrs_name, mysql_connattrs_value);
    free(mysql_connattrs_name);
    free(mysql_connattrs_value);
    return name_len + val_len;
}

static void
mysql_dissect_auth_switch_request(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    LOG_INFO("Auth Switch Request");
    mysql_set_conn_state(conn_data, AUTH_SWITCH_RESPONSE);

    /* Status (Always 0xfe) */
    uint8_t request_status = buf_readInt8(buf);
    UNUSED(request_status);

    /* name */
    buf_readCStr(buf, g_buf, BUFSZ);
    LOG_INFO("Request Name: %s", g_buf);

    /* Data */
    buf_readCStr(buf, g_buf, BUFSZ);
    LOG_INFO("Request Data: %s", g_buf);
}

static void
mysql_dissect_auth_switch_response(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    buf_readCStr(buf, g_buf, BUFSZ);
    LOG_INFO("Auth Switch Response, Data: %s", g_buf);
}

/*, packet_info *pinfo, */
static void
mysql_dissect_request(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    if (conn_data->state == AUTH_SWITCH_RESPONSE)
    {
        LOG_INFO("Request");
        mysql_dissect_auth_switch_response(buf, conn_data);
        return;
    }

    int opcode = buf_readInt8(buf);
    LOG_INFO("Request Opcode 0x%02x %s", opcode, mysql_get_command(opcode, "未知命令"));

    switch (opcode)
    {

    case MYSQL_QUIT:
        break;

    case MYSQL_PROCESS_INFO:
        mysql_set_conn_state(conn_data, RESPONSE_TABULAR);
        break;

    case MYSQL_DEBUG:
    case MYSQL_PING:
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_STATISTICS:
        mysql_set_conn_state(conn_data, RESPONSE_MESSAGE);
        break;

    case MYSQL_INIT_DB:
    case MYSQL_CREATE_DB:
    case MYSQL_DROP_DB:
        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql Schema: %s", g_buf);
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_QUERY:
        buf_readStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql Query: %s", g_buf);
        mysql_set_conn_state(conn_data, RESPONSE_TABULAR);
        break;

    case MYSQL_STMT_PREPARE:
        buf_readStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql Query: %s", g_buf);
        mysql_set_conn_state(conn_data, RESPONSE_PREPARE);
        break;

    case MYSQL_STMT_CLOSE:
    {
        uint32_t stmt_id = buf_readInt32LE(buf);
        LOG_INFO("Mysql Statement Close %u", stmt_id);
        mysql_set_conn_state(conn_data, REQUEST);
    }
    break;

    case MYSQL_STMT_RESET:
    {
        uint32_t stmt_id = buf_readInt32LE(buf);
        LOG_INFO("Mysql Reset Statement %u", stmt_id);
        mysql_set_conn_state(conn_data, RESPONSE_OK);
    }
    break;

    case MYSQL_FIELD_LIST:
        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql Table Name %s", g_buf);
        mysql_set_conn_state(conn_data, RESPONSE_SHOW_FIELDS);
        break;

    case MYSQL_PROCESS_KILL:
    {
        uint32_t mysql_thd_id = buf_readInt32LE(buf);
        LOG_INFO("Mysql Kill Thread ID %u", mysql_thd_id);
    }
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_CHANGE_USER:
    {
        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql User %s", g_buf);

        if (conn_data->clnt_caps & MYSQL_CAPS_SC)
        {
            int len = buf_readInt8(buf);
            buf_readStr(buf, g_buf, len);
        }
        else
        {
            buf_readCStr(buf, g_buf, BUFSZ);
        }
        LOG_INFO("Mysql Password: ");
        mysql_print_bytes(g_buf, strlen(g_buf));

        buf_readCStr(buf, g_buf, BUFSZ);
        LOG_INFO("Mysql Schema %s", g_buf);

        if (buf_readable(buf))
        {
            uint8_t charset = buf_readInt8(buf);
            buf_retrieve(buf, 1);
            LOG_INFO("Charset [%s](0x%02x)", mysql_get_charset(charset, "未知编码"), charset);
        }
    }
        mysql_set_conn_state(conn_data, RESPONSE_OK);

        /* optional: authentication plugin */
        if (conn_data->clnt_caps_ext & MYSQL_CAPS_PA)
        {
            mysql_set_conn_state(conn_data, AUTH_SWITCH_REQUEST);
            buf_readCStr(buf, g_buf, BUFSZ);
            LOG_INFO("Mysql Client Auth Plugin %s", g_buf);
        }

        /* optional: connection attributes */
        if (conn_data->clnt_caps_ext & MYSQL_CAPS_CA)
        {
            uint64_t lenfle;
            int length;
            uint64_t connattrs_length = buf_readFle(buf, &lenfle, NULL);
            while (connattrs_length > 0)
            {
                length = mysql_dissect_attributes(buf);
                connattrs_length -= length;
            }
        }
        break;

    case MYSQL_REFRESH:
    {
        uint8_t mysql_refresh = buf_readInt8(buf);
        char *tofree = mysql_get_refresh_val(mysql_refresh, "未知");
        LOG_INFO("Mysql Refresh %s(0x%02x)", tofree, mysql_refresh);
        free(tofree);
    }
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_SHUTDOWN:
    {
        uint8_t mysql_shutdown = buf_readInt8(buf);
        LOG_INFO("Mysql Shutdown Level %s(%d)", mysql_get_shutdown_val(mysql_shutdown, "未知"), mysql_shutdown);
    }
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_SET_OPTION:
    {
        uint16_t mysql_option = buf_readInt16LE(buf);
        LOG_INFO("Mysql Set Option %s(0x%04x)", mysql_get_option_val(mysql_option, "未知"), mysql_option);
    }
        mysql_set_conn_state(conn_data, RESPONSE_OK);
        break;

    case MYSQL_STMT_FETCH:
    {
        uint32_t stmt_id = buf_readInt32LE(buf);
        uint32_t num_rows = buf_readInt32LE(buf);
        LOG_INFO("Mysql Statement Fetch StmtId %u NumRows %u", stmt_id, num_rows);
    }
        mysql_set_conn_state(conn_data, RESPONSE_TABULAR);
        break;

    case MYSQL_STMT_SEND_LONG_DATA:
    {
        uint32_t stmt_id = buf_readInt32LE(buf);
        khint_t k = kh_get(stmts, conn_data->stmts, stmt_id);
        int is_missing = (k == kh_end(conn_data->stmts));
        if (is_missing)
        {
            buf_retrieve(buf, 2);
        }
        else
        {
            struct mysql_stmt_data *stmt_data = kh_value(conn_data->stmts, stmt_id);
            uint16_t data_param = buf_readInt16(buf);
            if (stmt_data->nparam > data_param)
            {
                stmt_data->param_flags[data_param] |= MYSQL_PARAM_FLAG_STREAMED;
            }
        }
    }

        if (buf_readable(buf))
        {
            buf_readCStr(buf, g_buf, BUFSZ);
            // LOG_INFO("Mysql Payload: %s", g_buf); // TODO null str ???
        }
        mysql_set_conn_state(conn_data, REQUEST);
        break;

    case MYSQL_STMT_EXECUTE:
    {
        uint32_t stmt_id = buf_readInt32LE(buf);
        uint8_t exec_flags = buf_readInt8(buf);
        uint32_t exec_iter = buf_readInt32LE(buf);

        // 注意: 这里是+5.x协议, 不适用于4.x
        LOG_INFO("Mysql Statement Id %u, Flags %s(0x%02x), Iter %u",
                 stmt_id, mysql_get_exec_flags_val(exec_flags, "未知"), exec_flags, exec_iter);

        khint_t k = kh_get(stmts, conn_data->stmts, stmt_id);
        int is_missing = (k == kh_end(conn_data->stmts));
        // 无元信息, 无法解析 STMT 参数~
        if (is_missing)
        {
            if (buf_readable(buf))
            {
                buf_readCStr(buf, g_buf, BUFSZ);
                // mysql prepare response needed
                // LOG_INFO("Mysql Payload: %s", g_buf); // TODO null str ???
            }
        }
        else
        {
            struct mysql_stmt_data *stmt_data = kh_value(conn_data->stmts, stmt_id);
            if (stmt_data->nparam != 0)
            {
                int n = (stmt_data->nparam + 7) / 8; /* NULL bitmap */
                buf_retrieve(buf, n);

                uint8_t stmt_bound = buf_readInt8(buf);
                LOG_INFO("Mysql Parameter Bound: %s", mysql_get_parameter_bound_val(stmt_bound, "未知"));

                if (stmt_bound == 1) // First Call Or Rebound
                {
                    int stmt_pos;
                    // 内存布局: 类型1(2byte),类型2(2byte),...值1,值2
                    int param_idx = buf_getReadIndex(buf) + stmt_data->nparam * 2;
                    for (stmt_pos = 0; stmt_pos < stmt_data->nparam; stmt_pos++)
                    {
                        if (!mysql_dissect_exec_param(buf, &param_idx, stmt_data->param_flags[stmt_pos]))
                            break;
                    }
                }
                else
                {
                    // TODO
                }
            }
        }

        // TODO 计算 value 的总长度
        // 消耗掉 已经处理的 value, 和可能附加的其他数据
        buf_retrieveAll(buf);
    }
        mysql_set_conn_state(conn_data, RESPONSE_TABULAR);
        break;

    case MYSQL_BINLOG_DUMP:
    {
        uint32_t binlog_position = buf_readInt32LE(buf);
        uint16_t binlog_flags = buf_readInt16(buf); // BIG_ENDIAN !!!
        uint32_t binlog_server_id = buf_readInt32LE(buf);
        LOG_INFO("Mysql Binlog Dump binlogPosition %u binlogFlags 0x%04x binlogServerId %u",
                 binlog_position, binlog_flags, binlog_server_id);
    }

        /* binlog file name ? */
        if (buf_readable(buf))
        {
            buf_readCStr(buf, g_buf, BUFSZ);
            LOG_INFO("Mysql Binlog File Name %s", g_buf);
        }

        mysql_set_conn_state(conn_data, REQUEST);
        break;

    case MYSQL_TABLE_DUMP:
    case MYSQL_CONNECT_OUT:
    case MYSQL_REGISTER_SLAVE:
        LOG_ERROR("Unsupport Mysql Replication Packets")
        mysql_set_conn_state(conn_data, REQUEST);
        break;

    default:
        mysql_set_conn_state(conn_data, UNDEFINED);
    }
}

static void
mysql_dissect_response(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    uint16_t server_status = 0;
    // uint8_t response_code = buf_readInt8(buf);
    uint8_t response_code = buf_peekInt8(buf);

    if (response_code == 0xff)
    { // ERR
        LOG_INFO("Response Code Error 0x%02x", response_code);
        buf_retrieve(buf, sizeof(uint8_t));
        mysql_dissect_error_packet(buf);
        mysql_set_conn_state(conn_data, REQUEST);
    }
    /*
    注：由于EOF值与其它Result Set结构共用1字节，所以在收到报文后需要对EOF包的真实性进行校验，
    校验条件为：
        第1字节值为0xFE
        包长度小于9字节
        附：EOF结构的相关处理函数：服务器：protocol.cc源文件中的send_eof函数
    
    其他资料:
    关于 EOF 包的废弃:
    https://dev.mysql.com/worklog/task/?id=7766

if buff[0] == 254 and length of buff is less than 9 bytes then its an
EOF packet.
    */
    else if (response_code == 0xfe && buf_readable(buf) < 9)
    { // EOF  !!! < 9
        LOG_INFO("Response Code EOF 0x%02x", response_code);
        uint8_t mysql_eof = buf_readInt8(buf);
        LOG_INFO("EOF Marker 0x%02x", mysql_eof);

        /* pre-4.1 packet ends here */
        if (buf_readable(buf))
        {
            uint16_t warn_num = buf_readInt16LE(buf);
            server_status = buf_readInt16LE(buf);
            LOG_INFO("Warnings %d", warn_num);
            char *tofree = mysql_get_server_status_val(server_status, "未知");
            LOG_INFO("Server Status %s (0x%04x)", tofree, server_status);
            free(tofree);
        }

        switch (conn_data->state)
        {
        case FIELD_PACKET:
            // 解析完 字段元信息, 继续解析 具体 Row
            mysql_set_conn_state(conn_data, ROW_PACKET);
            break;
        case ROW_PACKET:
            // 解析完 RowPacket 决定继续解析 还是等待 Request
            if (server_status & MYSQL_STAT_MU)
            {
                mysql_set_conn_state(conn_data, RESPONSE_TABULAR);
            }
            else
            {
                mysql_set_conn_state(conn_data, REQUEST);
            }
            break;
        case PREPARED_PARAMETERS:
            if (conn_data->stmt_num_fields > 0)
            {
                mysql_set_conn_state(conn_data, PREPARED_FIELDS);
            }
            else
            {
                mysql_set_conn_state(conn_data, REQUEST);
            }
            break;
        case PREPARED_FIELDS:
            mysql_set_conn_state(conn_data, REQUEST);
            break;
        default:
            /* This should be an unreachable case */
            mysql_set_conn_state(conn_data, REQUEST);
        }
    }
    /*
2017-12-03 修改 OK Packet 确认逻辑,  加入 > 9 逻辑
参见:https://dev.mysql.com/worklog/task/?id=7766
if buff[0] == 0 and length of buff is greater than 7 bytes then its an
OK packet.
> 9 的逻辑针对旧协议不适用 !!!
    */
    else if (response_code == 0x00 /*&& buf_readable(buf) > 9*/)
    { // OK
        LOG_INFO("Response Code OK 0x%02x", response_code);
        if (conn_data->state == RESPONSE_PREPARE)
        {
            mysql_dissect_response_prepare(buf, conn_data);
        }
        else if (buf_readable(buf) > buf_peekFleLen(buf))
        {
            mysql_dissect_ok_packet(buf, conn_data);
            if (conn_data->compressed_state == MYSQL_COMPRESS_INIT)
            {
                /* This is the OK packet which follows the compressed protocol setup */
                conn_data->compressed_state = MYSQL_COMPRESS_ACTIVE;
                // TODO
                // PANIC("MYSQL_COMPRESS NOT SUPPORT");
            }
        }
        else
        {
            mysql_dissect_result_header(buf, conn_data);
        }
    }
    else
    {
        switch (conn_data->state)
        {
        case RESPONSE_MESSAGE:
            buf_readStr(buf, g_buf, BUFSZ); // 读取所有
            LOG_INFO("Message %s", g_buf);
            mysql_set_conn_state(conn_data, REQUEST);
            break;

        // 处理查询结果集
        case RESPONSE_TABULAR:
            mysql_dissect_result_header(buf, conn_data);
            break;

        case FIELD_PACKET:
        case RESPONSE_SHOW_FIELDS:
        case RESPONSE_PREPARE:
        case PREPARED_PARAMETERS:
            /*
            原来的判断逻辑: 
            当 N 个 field packet 发送完成 之后, 会受到一个 EOF Packet
            如果 当前状态为 FIELD_PACKET, 则变更为 ROW_PACKET, 下一个包则按照 row packet 来解析

参见: https://dev.mysql.com/worklog/task/?id=7766
Metadata result set will no longer be terminated with EOF packet as the field
count information present will be enough for client to process the metadata.
Row result set(Text or Binary) will now be terminated with OK packet.

            因为有 field count 信息, 所以字段元信息只有不再发送 EOF packet
            现在在 conn_data 加上 num_fields, 用来计数判断
            原本 ResultSet 最后仍然会有 EOF 包, 现在替换为 OK Packet

            而且:
            因为抓包开始时候可能已经错过了 Login Request Phase, 所以无从得知 Client Cap
            1. 要通过 Client Cap 判断, 
            2. 也要通过 Fields Count 剩余来判断
            */

            // FIX 5.7 EOF 问题
            if (conn_data->num_fields == 0)
            {
                mysql_dissect_row_packet(buf);
                return;
            }

            mysql_dissect_field_packet(buf, conn_data);
            conn_data->num_fields--;

            if ((conn_data->clnt_caps_ext & MYSQL_CAPS_DE) && (conn_data->num_fields == 0))
            {
                LOG_ERROR("CLIENT 废弃 EOF");
                mysql_set_conn_state(conn_data, ROW_PACKET);
            }
            break;

        case ROW_PACKET:
            mysql_dissect_row_packet(buf);
            break;

        case PREPARED_FIELDS:
            mysql_dissect_field_packet(buf, conn_data);
            break;

        case AUTH_SWITCH_REQUEST:
            mysql_dissect_auth_switch_request(buf, conn_data);
            break;

        default:
            // 未知状态, 数据丢弃
            mysql_set_conn_state(conn_data, UNDEFINED);
            break;
        }
    }
}

static void
mysql_dissect_result_header(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    LOG_INFO("Tabular");
    uint64_t num_fields = buf_readFle(buf, NULL, NULL);
    LOG_INFO("num fields %" PRIu64, num_fields);
    // FIX 5.7 EOF 问题
    conn_data->num_fields = num_fields;
    conn_data->cur_field = 0;
    if (buf_readable(buf))
    {
        uint64_t extra = buf_readFle(buf, NULL, NULL);
        LOG_INFO("extra %" PRIu64, extra);
    }

    if (num_fields)
    {
        mysql_set_conn_state(conn_data, FIELD_PACKET);
    }
    else
    {
        mysql_set_conn_state(conn_data, ROW_PACKET);
    }
}

static void
mysql_dissect_ok_packet(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    LOG_INFO("OK");

    uint64_t affected_rows = buf_readFle(buf, NULL, NULL);
    LOG_INFO("Affected Rows %" PRIu64, affected_rows);

    uint64_t insert_id = buf_readFle(buf, NULL, NULL);
    if (insert_id)
    {
        LOG_INFO("Last INSERT ID %" PRIu64, insert_id);
    }

    uint16_t server_status = 0;
    if (buf_readable(buf))
    {
        server_status = buf_readInt16LE(buf);
        char *tofree = mysql_get_server_status_val(server_status, "未知");
        LOG_INFO("Server Status %s (0x%04x)", tofree, server_status);
        free(tofree);

        /* 4.1+ protocol only: 2 bytes number of warnings */
        if (conn_data->clnt_caps & conn_data->srv_caps & MYSQL_CAPS_CU)
        {
            uint16_t warn_num = buf_readInt16LE(buf);
            LOG_INFO("Server Warnings %d", warn_num);
        }
    }

    if (conn_data->clnt_caps_ext & MYSQL_CAPS_ST)
    {
        if (buf_readable(buf))
        {
            int length;

            int lenstr = buf_readFle(buf, NULL, NULL);
            /* first read the optional message */
            if (lenstr)
            {
                buf_readStr(buf, g_buf, lenstr);
                LOG_INFO("Session Track Message %s", g_buf);
            }

            /* session state tracking */
            if (server_status & MYSQL_STAT_SESSION_STATE_CHANGED)
            {
                uint64_t session_track_length = buf_readFle(buf, NULL, NULL);
                LOG_INFO("Session Track Length %" PRIu64, session_track_length);

                while (session_track_length > 0)
                {
                    length = mysql_dissect_session_tracker_entry(buf);
                    session_track_length -= length;
                }
            }
        }
    }
    else
    {
        /* optional: message string */
        if (buf_readable(buf))
        {
            buf_readCStr(buf, g_buf, BUFSZ);
            LOG_INFO("Message %s", g_buf);
        }
    }

    mysql_set_conn_state(conn_data, REQUEST);
}

static void
mysql_dissect_field_packet(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    conn_data->cur_field++;
    LOG_INFO("Field %" PRIu64, conn_data->cur_field);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Catalog %s", g_buf);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Database %s", g_buf);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Table %s", g_buf);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Original Table %s", g_buf);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Name %s", g_buf);

    buf_readFleStr(buf, g_buf, BUFSZ);
    LOG_INFO("Orginal Name %s", g_buf);

    buf_retrieve(buf, 1);

    uint16_t charset = buf_readInt16LE(buf);
    uint32_t length = buf_readInt32LE(buf);
    uint8_t type = buf_readInt8(buf);
    uint16_t flags = buf_readInt16LE(buf);
    uint8_t decimal = buf_readInt8(buf);
    LOG_INFO("Charset [%s](0x%02x)", mysql_get_charset(charset, "未知"), charset);
    LOG_INFO("Length %d", length);
    LOG_INFO("Type [%s](%d)", mysql_get_field_type(type, "未知"), type);
    char *tofree = mysql_get_field_flags_val(flags, "未知");
    LOG_INFO("Flags %s (0x%04x)", tofree, flags);
    free(tofree);

    LOG_INFO("Decimal %d", decimal);

    buf_retrieve(buf, 2);

    /* default (Only use for show fields) */
    if (buf_readable(buf))
    {
        buf_readFleStr(buf, g_buf, BUFSZ);
        LOG_INFO("Default %s", g_buf);
    }
}

/*
  Add a session track entry to the session tracking subtree

  return bytes read
*/
static int
mysql_dissect_session_tracker_entry(struct buffer *buf)
{

    uint64_t lenstr;
    uint64_t lenfle;

    /* session tracker type */
    uint8_t data_type = buf_readInt8(buf);
    LOG_INFO("Mysql Session Tracker Type: %s(%d)", mysql_get_session_track_type(data_type, "未知"), data_type);
    uint64_t length = buf_readFle(buf, &lenfle, NULL); /* complete length of session tracking entry */
    int sz = 1 + lenfle + length;

    switch (data_type)
    {
    case 0: /* SESSION_SYSVARS_TRACKER */
        lenstr = buf_readFle(buf, &lenfle, NULL);
        buf_readStr(buf, g_buf, lenstr);
        LOG_INFO("Session Track Sysvar Name %s", g_buf);

        lenstr = buf_readFle(buf, &lenfle, NULL);
        buf_readStr(buf, g_buf, lenstr);
        LOG_INFO("Session Track Sysvar Value %s", g_buf);
        break;
    case 1: /* CURRENT_SCHEMA_TRACKER */
        lenstr = buf_readFle(buf, &lenfle, NULL);
        buf_readStr(buf, g_buf, lenstr);
        LOG_INFO("Session Track Sysvar Schema %s", g_buf);
        break;
    case 2: /* SESSION_STATE_CHANGE_TRACKER */
        LOG_INFO("Session Track State Change");
        break;
    default: /* unsupported types skipped */
        LOG_INFO("UnSupported Session Track Types");
    }

    return sz;
}

static void
mysql_dissect_row_packet(struct buffer *buf)
{
    while (buf_readable(buf))
    {
        uint8_t is_null;
        uint64_t lelen = buf_readFle(buf, NULL, &is_null);
        if (is_null)
        {
            LOG_INFO("NULL");
        }
        else
        {
            buf_readStr(buf, g_buf, lelen);
            LOG_INFO("Text: %s", g_buf);
        }
    }
}

static const mysql_exec_dissector_t mysql_exec_dissectors[] = {
    {0x01, 0, mysql_dissect_exec_tiny},
    {0x02, 0, mysql_dissect_exec_short},
    {0x03, 0, mysql_dissect_exec_long},
    {0x04, 0, mysql_dissect_exec_float},
    {0x05, 0, mysql_dissect_exec_double},
    {0x06, 0, mysql_dissect_exec_null},
    {0x07, 0, mysql_dissect_exec_datetime},
    {0x08, 0, mysql_dissect_exec_longlong},
    {0x0a, 0, mysql_dissect_exec_datetime},
    {0x0b, 0, mysql_dissect_exec_time},
    {0x0c, 0, mysql_dissect_exec_datetime},
    {0xf6, 0, mysql_dissect_exec_string},
    {0xfc, 0, mysql_dissect_exec_string},
    {0xfd, 0, mysql_dissect_exec_string},
    {0xfe, 0, mysql_dissect_exec_string},
    {0x00, 0, NULL},
};

static void
mysql_dissect_exec_string(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);
    *param_idx += sizeof(uint8_t);

    uint32_t param_len = buf_readInt8(buf);

    switch (param_len)
    {
    case 0xfc: /* 252 - 64k chars */
        param_len = buf_readInt16LE(buf);
        *param_idx += sizeof(uint16_t);
        break;
    case 0xfd: /* 64k - 16M chars */
        param_len = buf_readInt32LE24(buf);
        *param_idx += 3;
        break;
    default: /* < 252 chars */
        break;
    }

    buf_readStr(buf, g_buf, param_len);
    LOG_INFO("String %s", g_buf);
    *param_idx += param_len;

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_time(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint8_t param_len = buf_readInt8(buf);
    *param_idx += sizeof(uint8_t);

    // TODO struct
    uint8_t sign = 0;
    uint32_t days = 0;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
    uint32_t second_b = 0; // Billionth of a second

    if (param_len >= 1)
    {
        sign = buf_readInt8(buf);
        *param_idx += sizeof(uint8_t);
    }
    if (param_len >= 5)
    {
        days = buf_readInt32LE(buf);
        *param_idx += 3;
    }
    if (param_len >= 8)
    {
        hour = buf_readInt8(buf);
        minute = buf_readInt8(buf);
        second = buf_readInt8(buf);
        *param_idx += sizeof(uint8_t);
        *param_idx += sizeof(uint8_t);
        *param_idx += sizeof(uint8_t);
    }
    if (param_len >= 12)
    {
        second_b = buf_readInt32LE(buf);
        *param_idx += sizeof(uint32_t);
    }

    // 处理掉 > 12 部分
    if (param_len - 12)
    {
        buf_retrieve(buf, param_len - 12);
        *param_idx += param_len - 12;
    }

    buf_setReadIndex(buf, idx);

    LOG_INFO("Mysql Time %s%d:%d:%d.%d",
        mysql_get_time_sign(sign, ""), days * 24 + hour, minute, second, second_b);
}

static void
mysql_dissect_exec_datetime(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint8_t param_len = buf_readInt8(buf);
    *param_idx += sizeof(uint8_t);

    // TODO struct
    uint16_t year = 0;
    uint8_t month = 0;
    uint8_t day = 0;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
    uint32_t second_b = 0; // Billionth of a second

    if (param_len >= 2)
    {
        year = buf_readInt16LE(buf);
        *param_idx += sizeof(uint16_t);
    }
    if (param_len >= 4)
    {
        month = buf_readInt8(buf);
        day = buf_readInt8(buf);
        *param_idx += sizeof(uint8_t);
        *param_idx += sizeof(uint8_t);
    }
    if (param_len >= 7)
    {
        hour = buf_readInt8(buf);
        minute = buf_readInt8(buf);
        second = buf_readInt8(buf);
        *param_idx += sizeof(uint8_t);
        *param_idx += sizeof(uint8_t);
        *param_idx += sizeof(uint8_t);
    }
    if (param_len >= 11)
    {
        second_b = buf_readInt32LE(buf);
        *param_idx += sizeof(uint32_t);
    }

    // 处理掉 > 12 部分
    if (param_len - 11)
    {
        buf_retrieve(buf, param_len - 11);
        *param_idx += param_len - 11;
    }

    buf_setReadIndex(buf, idx);

    LOG_INFO("Mysql Datetime %d-%d-%d %d:%d:%d.%d",
            year, month, day, hour, minute, second, second_b);
}

static void
mysql_dissect_exec_tiny(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint8_t mysql_exec_field_tiny = buf_peekInt8(buf);
    *param_idx += sizeof(uint8_t);

    if (param_unsigned)
    {
        LOG_INFO("Mysql Exec Tiny %hhu", mysql_exec_field_tiny);
    }
    else
    {
        LOG_INFO("Mysql Exec Tiny %hhd", (int8_t)mysql_exec_field_tiny);
    }

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_short(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint16_t mysql_exec_field_short = buf_peekInt16LE(buf);
    *param_idx += sizeof(uint16_t);
    if (param_unsigned)
    {
        LOG_INFO("Mysql Exec Short %hu", mysql_exec_field_short);
    }
    else
    {
        LOG_INFO("Mysql Exec Short %hd", (int16_t)mysql_exec_field_short);
    }

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_long(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint32_t mysql_exec_field_long = buf_peekInt32LE(buf);
    *param_idx += sizeof(uint32_t);
    if (param_unsigned)
    {
        LOG_INFO("Mysql Exec Long %u", mysql_exec_field_long);
    }
    else
    {
        LOG_INFO("Mysql Exec Long %d", (int32_t)mysql_exec_field_long);
    }

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_float(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    // 注意 这里不是小端
    float mysql_exec_field_float = *((float *)buf_peek(buf));
    *param_idx += sizeof(uint32_t);
    LOG_INFO("Mysql Exec Float %f", mysql_exec_field_float);

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_double(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    // 注意 这里不是小端
    double mysql_exec_field_double = *((double *)buf_peek(buf));
    *param_idx += sizeof(uint64_t);
    LOG_INFO("Mysql Exec Double %f", mysql_exec_field_double);

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_longlong(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    int idx = buf_getReadIndex(buf);
    buf_setReadIndex(buf, *param_idx);

    uint64_t mysql_exec_field_longlong = buf_peekInt64LE(buf);
    *param_idx += sizeof(uint64_t);
    if (param_unsigned)
    {
        LOG_INFO("Mysql Exec LongLong %" PRIu64, mysql_exec_field_longlong);
    }
    else
    {
        LOG_INFO("Mysql Exec LongLong %" PRId64, (int64_t)mysql_exec_field_longlong);
    }

    buf_setReadIndex(buf, idx);
}

static void
mysql_dissect_exec_null(struct buffer *buf, uint8_t param_unsigned, int *param_idx)
{
    LOG_INFO("Mysql Exec NULL");
    // TODO test NULL 是否消耗 value 字节数
}

// length coded binary: a variable-length number
// Length Coded String: a variable-length string.
// Used instead of Null-Terminated String,
// especially for character strings which might contain '/0' or might be very long.
// The first part of a Length Coded String is a Length Coded Binary number (the length);
// the second part of a Length Coded String is the actual data. An example of a short
// Length Coded String is these three hexadecimal bytes: 02 61 62, which means "length = 2, contents = 'ab'".

static char
mysql_dissect_exec_param(struct buffer *buf, int *param_idx, uint8_t param_flags)
{
    int dissector_index = 0;

    uint8_t param_type = buf_readInt8(buf);
    uint8_t param_unsigned = buf_readInt8(buf); /* signedness */
    // LOG_ERROR("Type [%s](%d)", mysql_get_field_type(param_type, "未知类型"), param_type);

    if ((param_flags & MYSQL_PARAM_FLAG_STREAMED) == MYSQL_PARAM_FLAG_STREAMED)
    {
        LOG_INFO("Streamed Parameter");
        return 1;
    }
    while (mysql_exec_dissectors[dissector_index].dissector != NULL)
    {
        if (mysql_exec_dissectors[dissector_index].type == param_type &&
            mysql_exec_dissectors[dissector_index].unsigned_flag == param_unsigned)
        {
            mysql_exec_dissectors[dissector_index].dissector(buf, param_unsigned, param_idx);
            return 1;
        }
        dissector_index++;
    }
    return 0;
}

static void
mysql_dissect_response_prepare(struct buffer *buf, mysql_conn_data_t *conn_data)
{
    /* 0, marker for OK packet */
    buf_retrieve(buf, 1);
    uint32_t stmt_id = buf_readInt32LE(buf);
    conn_data->stmt_num_fields = buf_readInt16LE(buf);
    conn_data->stmt_num_params = buf_readInt16LE(buf);

    LOG_INFO("Mysql Statement Id %u, Fields %u, Params %u",
             stmt_id, conn_data->stmt_num_fields, conn_data->stmt_num_params);

    // FIX 5.7 EOF 问题
    // TODO TODO
    conn_data->num_fields = conn_data->stmt_num_params;

    struct mysql_stmt_data *stmt_data = mysql_stmt_data_create(conn_data->stmt_num_params);
    assert(stmt_data);

    int absent;
    khint_t k = kh_put(stmts, conn_data->stmts, stmt_id, &absent);
    if (!absent)
    {
        kh_del(stmts, conn_data->stmts, k);
    }
    kh_value(conn_data->stmts, k) = stmt_data;

    /* Filler */
    buf_retrieve(buf, 1);

    // TODO
    // uint16_t warn_num = buf_readInt16LE(buf);
    // LOG_INFO("Warnings %d", warn_num);

    if (conn_data->stmt_num_params > 0)
    {
        mysql_set_conn_state(conn_data, PREPARED_PARAMETERS);
    }
    else if (conn_data->stmt_num_fields > 0)
    {
        mysql_set_conn_state(conn_data, PREPARED_FIELDS);
    }
    else
    {
        mysql_set_conn_state(conn_data, REQUEST);
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

void pkt_handle(void *ud,
                const struct pcap_pkthdr *pkt_hdr,
                const struct ip *ip_hdr,
                const struct tcphdr *tcp_hdr,
                const struct tcpopt *tcp_opt,
                const u_char *payload,
                size_t payload_size)
{
    static struct tuple4 t4;
    static char s_ip_buf[INET_ADDRSTRLEN];
    static char d_ip_buf[INET_ADDRSTRLEN];

    uint32_t s_ip = ip_hdr->ip_src.s_addr;
#ifdef __APPLE__
    uint16_t s_port = ntohs(tcp_hdr->th_sport);
#else
    uint16_t s_port = ntohs(tcp_hdr->source);
#endif

    uint32_t d_ip = ip_hdr->ip_dst.s_addr;
#ifdef __APPLE__
    uint16_t d_port = ntohs(tcp_hdr->th_dport);
#else
    uint16_t d_port = ntohs(tcp_hdr->dest);
#endif

    inet_ntop(AF_INET, &(ip_hdr->ip_src.s_addr), s_ip_buf, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst.s_addr), d_ip_buf, INET_ADDRSTRLEN);

#ifdef __APPLE__
    printf("%s:%d > %s:%d ack %u, seq %u, sz %zd\n", s_ip_buf, s_port, d_ip_buf, d_port,
           ntohl(tcp_hdr->th_ack), ntohl(tcp_hdr->th_seq), payload_size);
#else
    printf("%s:%d > %s:%d ack %u, seq %u, sz %zd\n", s_ip_buf, s_port, d_ip_buf, d_port,
           ntohl(tcp_hdr->ack_seq), ntohl(tcp_hdr->seq), payload_size);
#endif

    struct mysql_ss *ss = (struct mysql_ss *)ud;
    mysql_tuple4_init(&t4, s_ip, s_port, d_ip, d_port);

// 连接关闭, 清理数据
#ifdef __APPLE__
    if (tcp_hdr->th_flags & TH_FIN || tcp_hdr->th_flags & TH_RST)
#else
    if (tcp_hdr->fin || tcp_hdr->rst)
#endif

    {
        LOG_INFO("%s:%d > %s:%d Close Connection", s_ip_buf, s_port, d_ip_buf, d_port);
        mysql_ss_del(ss, &t4);
        return;
    }

    if (payload_size <= 0)
    {
        return;
    }

    bool is_response;
    struct mysql_session *s = mysql_ss_get(ss, &t4);
    struct buffer *buf = mysql_session_getbuf(s, &t4, s_port, &is_response);
    buf_append(buf, (const char *)payload, payload_size);

    // 一个 tcp segment 包括 N 个 Mysql Packet
    while (mysql_is_completed_pdu(buf))
    {
        if (s->conn_data->frame_start_compressed &&
            s->conn_data->compressed_state == MYSQL_COMPRESS_ACTIVE)
        {
            LOG_INFO("Start Compressed Active");
            /*
 * Decode the header of a compressed packet
 * https://dev.mysql.com/doc/internals/en/compressed-packet-header.html
 */
            int32_t cmp_pkt_sz = buf_readInt32LE24(buf);
            uint8_t cmp_pkt_num = buf_readInt8(buf);
            int32_t cmp_pkt_uncmp_sz = buf_readInt32LE24(buf);

            UNUSED(cmp_pkt_sz);
            UNUSED(cmp_pkt_num);
            UNUSED(cmp_pkt_uncmp_sz);
        }

        int32_t pkt_sz = buf_readInt32LE24(buf);
        uint8_t pkt_num = buf_readInt8(buf);
        LOG_INFO("%s:%d > %s:%d pkt_sz %d, pkt_no %d", s_ip_buf, s_port, d_ip_buf, d_port, pkt_sz, pkt_num);

        // 这里不用担心频繁创建只读视图, 内部有缓存
        struct buffer *rbuf = buf_readonlyView(buf, pkt_sz);
        buf_retrieve(buf, pkt_sz);

        // TODO 检测是否是 SSL !!!
        bool is_ssl = false;

        if (is_response)
        {
            if (pkt_num == 0 && s->conn_data->state == UNDEFINED)
            {
                mysql_dissect_greeting(rbuf, s->conn_data);
            }
            else
            {
                mysql_dissect_response(rbuf, s->conn_data);
            }
        }
        else
        {
            // TODO 这里 有问题, 暂时没进入该分支 !!!!, 抓取不到 login
            if (s->conn_data->state == LOGIN && (pkt_num == 1 || (pkt_num == 2 && is_ssl)))
            {
                mysql_dissect_login(rbuf, s->conn_data);
                if ((s->conn_data->srv_caps & MYSQL_CAPS_CP) && (s->conn_data->clnt_caps & MYSQL_CAPS_CP))
                {
                    s->conn_data->frame_start_compressed = 1;
                    s->conn_data->compressed_state = MYSQL_COMPRESS_INIT;
                }
            }
            else
            {
                mysql_dissect_request(rbuf, s->conn_data);
            }
        }
        buf_release(rbuf);
    }

    if (buf_internalCapacity(buf) > 1024 * 1024)
    {
        buf_shrink(buf, 0);
    }
}

/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

static void
usage()
{
    static const char *usage =
        "\nUsage:\n"
        "   mysql_sniff -i <interface> -p <mysql_server_port1>,<port2>,<port3>... [-v]\n\n"
        "Example:\n"
        "   mysql_sniff -i any -p 3306\n";
    puts(usage);
    exit(1);
}

// 不会修改 inputString, argv[0..cnt]分隔的字符串需要自行释放...
// _BSD_SOURCE string.h
static int str_split(const char *inputstring, const char *delim, char **argv, size_t argc)
{
    int cnt = 0;
    char *string, *tofree, **ap;
    tofree = string = strdup(inputstring);
    assert(string);

    for (ap = argv; (*ap = strsep(&string, delim)) != NULL;)
    {
        if (**ap != '\0')
        {
            *ap = strdup(*ap);
            cnt++;
            if (++ap >= &argv[argc])
            {
                break;
            }
        }
    }

    free(tofree);
    return cnt;
}

// 移除前缀后缀 space, 会修改原 char*, 记得备份释放
static char *str_trim(char *str, const char *trim)
{
    char *end;
    if (str == 0)
    {
        return 0;
    }

    while (isspace((int)*str) || strchr(trim, *str))
    {
        str++;
    }

    if (*str == 0)
    {
        return str;
    }

    end = str + strlen(str) - 1;
    while (end > str && (isspace((int)*end) || strchr(trim, *end)))
    {
        end--;
    }

    *(end + 1) = 0;

    return str;
}

#define ASSERT_OPT(assert, reason, ...)                                  \
    if (!(assert))                                                       \
    {                                                                    \
        fprintf(stderr, "\x1B[1;31m" reason "\x1B[0m\n", ##__VA_ARGS__); \
        usage();                                                         \
    }

struct mysql_sniff_opts
{
    char *interface;
    char *expression;
    bool verbose;
    int port_sz;
    uint16_t mysql_server_ports[0];
};

extern char *optarg;

int main(int argc, char **argv)
{
    UNUSED(str_split);
    const char *optString = "i:p:v?";
    char *port;
    int opt = 0, max_port_sz = 10, max_filter_sz = 100, i = 0;

    struct mysql_sniff_opts *opts = calloc(1, sizeof(*opts) + max_port_sz * sizeof(uint16_t));
    assert(opts);
    opts->expression = calloc(max_filter_sz, sizeof(char));
    assert(opts->expression);

    opt = getopt(argc, argv, optString);
    optarg = str_trim(optarg, "=");
    while (opt != -1)
    {
        switch (opt)
        {
        case 'i':
            opts->interface = strdup(optarg);
            assert(opts->interface);
            break;
        case 'p':
            // size_t needed = snprintf(NULL, 0, ,
            i += snprintf(opts->expression + i, max_filter_sz - i - 1, "tcp and ( port 0 ");
            assert(i <= max_filter_sz - 1);
            while ((port = strsep(&optarg, ",")) != NULL)
            {
                if (port)
                {
                    if (!atoi(port))
                    {
                        LOG_ERROR("端口号有误 %s", port);
                        goto free;
                    }
                    opts->mysql_server_ports[opts->port_sz++] = atoi(port);
                    i += snprintf(opts->expression + i, max_filter_sz - i - 1, "or port %d ", atoi(port));
                    assert(i <= max_filter_sz - 1);
                    if (opts->port_sz >= max_port_sz)
                    {
                        LOG_ERROR("端口数超限 max=%d", max_port_sz);
                        break;
                    }
                }
            }
            i += snprintf(opts->expression + i, max_filter_sz - i - 1, ")");
            assert(i <= max_filter_sz - 1);
            break;
        case 'v':
            opts->verbose = !!optarg;
            break;
        case '?':
            usage();
            break;
        default:
            break;
        }
        opt = getopt(argc, argv, optString);
        optarg = str_trim(optarg, "=");
    }
    if (!opts->interface)
    {
        opts->interface = strdup("eth0");
        assert(opts->interface);
    }
    ASSERT_OPT(opts->port_sz, "必须指定MysqlServer端口, -p=3306,3307,3308");

    struct mysql_ss *ss = mysql_ss_create(opts->mysql_server_ports, opts->port_sz);
    assert(ss);

    struct tcpsniff_opt sniffopt = {
        .snaplen = 65535,
        .pkt_cnt_limit = 0,
        .timeout_limit = 10,
        .device = opts->interface,
        .filter_exp = opts->expression,
        .ud = ss};

    LOG_INFO("interface %s, expression %s", opts->interface, opts->expression);

    tcpsniff(&sniffopt, pkt_handle); // 内部有错误输出, 不需要判断...

    mysql_ss_release(ss);

free:
    if (opts->interface)
    {
        free(opts->interface);
    }
    free(opts->expression);
    free(opts);

    return 0;
}