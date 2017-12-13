#ifndef MYSQL_SNIFF_H
#define MYSQL_SNIFF_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "buffer.h"

struct val_str
{
    uint32_t val;
    const char *str;
};

#if !defined(UNUSED)
#define UNUSED(x) ((void)(x))
#endif

#define MYSQL_MAX_PACKET_LEN 0xFFFFFF
// 超过体积 warning
#define MYSQL_WARN_PACKEt_LEN 1024 * 1024

/* client/server capabilities
 * http://dev.mysql.com/doc/internals/en/capability-flags.html
 */
#define MYSQL_CAPS_LP 0x0001 /* CLIENT_LONG_PASSWORD */
#define MYSQL_CAPS_FR 0x0002 /* CLIENT_FOUND_ROWS */
#define MYSQL_CAPS_LF 0x0004 /* CLIENT_LONG_FLAG */
#define MYSQL_CAPS_CD 0x0008 /* CLIENT_CONNECT_WITH_DB */
#define MYSQL_CAPS_NS 0x0010 /* CLIENT_NO_SCHEMA */
#define MYSQL_CAPS_CP 0x0020 /* CLIENT_COMPRESS */
#define MYSQL_CAPS_OB 0x0040 /* CLIENT_ODBC */
#define MYSQL_CAPS_LI 0x0080 /* CLIENT_LOCAL_FILES */
#define MYSQL_CAPS_IS 0x0100 /* CLIENT_IGNORE_SPACE */
#define MYSQL_CAPS_CU 0x0200 /* CLIENT_PROTOCOL_41 */
#define MYSQL_CAPS_IA 0x0400 /* CLIENT_INTERACTIVE */
#define MYSQL_CAPS_SL 0x0800 /* CLIENT_SSL */
#define MYSQL_CAPS_II 0x1000 /* CLIENT_IGNORE_SPACE */
#define MYSQL_CAPS_TA 0x2000 /* CLIENT_TRANSACTIONS */
#define MYSQL_CAPS_RS 0x4000 /* CLIENT_RESERVED */
#define MYSQL_CAPS_SC 0x8000 /* CLIENT_SECURE_CONNECTION */

/* field flags */
#define MYSQL_FLD_NOT_NULL_FLAG 0x0001
#define MYSQL_FLD_PRI_KEY_FLAG 0x0002
#define MYSQL_FLD_UNIQUE_KEY_FLAG 0x0004
#define MYSQL_FLD_MULTIPLE_KEY_FLAG 0x0008
#define MYSQL_FLD_BLOB_FLAG 0x0010
#define MYSQL_FLD_UNSIGNED_FLAG 0x0020
#define MYSQL_FLD_ZEROFILL_FLAG 0x0040
#define MYSQL_FLD_BINARY_FLAG 0x0080
#define MYSQL_FLD_ENUM_FLAG 0x0100
#define MYSQL_FLD_AUTO_INCREMENT_FLAG 0x0200
#define MYSQL_FLD_TIMESTAMP_FLAG 0x0400
#define MYSQL_FLD_SET_FLAG 0x0800

/* 
 * 参见最新协议文档: https://dev.mysql.com/doc/dev/mysql-server/8.0.1/group__group__cs__capabilities__flags.html
 * 
 * extended capabilities: 4.1+ client only
 *
 * These are libmysqlclient flags and NOT present
 * in the protocol:
 * CLIENT_SSL_VERIFY_SERVER_CERT (1UL << 30)
 * CLIENT_REMEMBER_OPTIONS (1UL << 31)
 */
#define MYSQL_CAPS_MS 0x0001 /* CLIENT_MULTI_STATMENTS */
#define MYSQL_CAPS_MR 0x0002 /* CLIENT_MULTI_RESULTS */
#define MYSQL_CAPS_PM 0x0004 /* CLIENT_PS_MULTI_RESULTS */
#define MYSQL_CAPS_PA 0x0008 /* CLIENT_PLUGIN_AUTH */
#define MYSQL_CAPS_CA 0x0010 /* CLIENT_CONNECT_ATTRS */
#define MYSQL_CAPS_AL 0x0020 /* CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA */
#define MYSQL_CAPS_EP 0x0040 /* CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS */
#define MYSQL_CAPS_ST 0x0080 /* CLIENT_SESSION_TRACK */
#define MYSQL_CAPS_DE 0x0100 /* CLIENT_DEPRECATE_EOF */
#define MYSQL_CAPS_UNUSED 0xFE00

/* status bitfield */
#define MYSQL_STAT_IT 0x0001
#define MYSQL_STAT_AC 0x0002
#define MYSQL_STAT_MR 0x0004
#define MYSQL_STAT_MU 0x0008
#define MYSQL_STAT_BI 0x0010
#define MYSQL_STAT_NI 0x0020
#define MYSQL_STAT_CR 0x0040
#define MYSQL_STAT_LR 0x0080
#define MYSQL_STAT_DR 0x0100
#define MYSQL_STAT_BS 0x0200
#define MYSQL_STAT_SESSION_STATE_CHANGED 0x0400
#define MYSQL_STAT_QUERY_WAS_SLOW 0x0800
#define MYSQL_STAT_PS_OUT_PARAMS 0x1000

/* bitfield for MYSQL_REFRESH */
#define MYSQL_RFSH_GRANT 1    /* Refresh grant tables */
#define MYSQL_RFSH_LOG 2      /* Start on new log file */
#define MYSQL_RFSH_TABLES 4   /* close all tables */
#define MYSQL_RFSH_HOSTS 8    /* Flush host cache */
#define MYSQL_RFSH_STATUS 16  /* Flush status variables */
#define MYSQL_RFSH_THREADS 32 /* Flush thread cache */
#define MYSQL_RFSH_SLAVE 64   /* Reset master info and restart slave thread */
#define MYSQL_RFSH_MASTER 128 /* Remove all bin logs in the index and truncate the index */

/* MySQL command codes */
#define MYSQL_SLEEP 0 /* not from client */
#define MYSQL_QUIT 1
#define MYSQL_INIT_DB 2
#define MYSQL_QUERY 3
#define MYSQL_FIELD_LIST 4
#define MYSQL_CREATE_DB 5
#define MYSQL_DROP_DB 6
#define MYSQL_REFRESH 7
#define MYSQL_SHUTDOWN 8
#define MYSQL_STATISTICS 9
#define MYSQL_PROCESS_INFO 10
#define MYSQL_CONNECT 11 /* not from client */
#define MYSQL_PROCESS_KILL 12
#define MYSQL_DEBUG 13
#define MYSQL_PING 14
#define MYSQL_TIME 15         /* not from client */
#define MYSQL_DELAY_INSERT 16 /* not from client */
#define MYSQL_CHANGE_USER 17
#define MYSQL_BINLOG_DUMP 18    /* replication */
#define MYSQL_TABLE_DUMP 19     /* replication */
#define MYSQL_CONNECT_OUT 20    /* replication */
#define MYSQL_REGISTER_SLAVE 21 /* replication */
#define MYSQL_STMT_PREPARE 22
#define MYSQL_STMT_EXECUTE 23
#define MYSQL_STMT_SEND_LONG_DATA 24
#define MYSQL_STMT_CLOSE 25
#define MYSQL_STMT_RESET 26
#define MYSQL_SET_OPTION 27
#define MYSQL_STMT_FETCH 28

/* MySQL cursor types */

#define MYSQL_CURSOR_TYPE_NO_CURSOR 0
#define MYSQL_CURSOR_TYPE_READ_ONLY 1
#define MYSQL_CURSOR_TYPE_FOR_UPDATE 2
#define MYSQL_CURSOR_TYPE_SCROLLABLE 4

/* MySQL parameter flags -- used internally by the dissector */

#define MYSQL_PARAM_FLAG_STREAMED 0x01

/* Compression states, internal to the dissector */
#define MYSQL_COMPRESS_NONE 0
#define MYSQL_COMPRESS_INIT 1
#define MYSQL_COMPRESS_ACTIVE 2

char *mysql_command_table[29] = {
    /*MYSQL_SLEEP*/ "SLEEP",
    /*MYSQL_QUIT*/ "Quit",
    /*MYSQL_INIT_DB*/ "Use Database",
    /*MYSQL_QUERY*/ "Query",
    /*MYSQL_FIELD_LIST*/ "Show Fields",
    /*MYSQL_CREATE_DB*/ "Create Database",
    /*MYSQL_DROP_DB */ "Drop Database",
    /*MYSQL_REFRESH */ "Refresh",
    /*MYSQL_SHUTDOWN */ "Shutdown",
    /*MYSQL_STATISTICS */ "Statistics",
    /*MYSQL_PROCESS_INFO */ "Process List",
    /*MYSQL_CONNECT */ "Connect",
    /*MYSQL_PROCESS_KILL */ "Kill Server Thread",
    /*MYSQL_DEBUG */ "Dump Debuginfo",
    /*MYSQL_PING */ "Ping",
    /*MYSQL_TIME */ "Time",
    /*MYSQL_DELAY_INSERT */ "Insert Delayed",
    /*MYSQL_CHANGE_USER */ "Change User",
    /*MYSQL_BINLOG_DUMP */ "Send Binlog",
    /*MYSQL_TABLE_DUMP*/ "Send Table",
    /*MYSQL_CONNECT_OUT*/ "Slave Connect",
    /*MYSQL_REGISTER_SLAVE*/ "Register Slave",
    /*MYSQL_STMT_PREPARE*/ "Prepare Statement",
    /*MYSQL_STMT_EXECUTE*/ "Execute Statement",
    /*MYSQL_STMT_SEND_LONG_DATA*/ "Send BLOB",
    /*MYSQL_STMT_CLOSE*/ "Close Statement",
    /*MYSQL_STMT_RESET*/ "Reset Statement",
    /*MYSQL_SET_OPTION*/ "Set Option",
    /*MYSQL_STMT_FETCH*/ "Fetch Data",
};

char *mysql_charset_table[216] = {
    /*0*/ "Unknown",
    /*1*/ "big5 COLLATE big5_chinese_ci",
    /*2*/ "latin2 COLLATE latin2_czech_cs",
    /*3*/ "dec8 COLLATE dec8_swedish_ci",
    /*4*/ "cp850 COLLATE cp850_general_ci",
    /*5*/ "latin1 COLLATE latin1_german1_ci",
    /*6*/ "hp8 COLLATE hp8_english_ci",
    /*7*/ "koi8r COLLATE koi8r_general_ci",
    /*8*/ "latin1 COLLATE latin1_swedish_ci",
    /*9*/ "latin2 COLLATE latin2_general_ci",
    /*10*/ "swe7 COLLATE swe7_swedish_ci",
    /*11*/ "ascii COLLATE ascii_general_ci",
    /*12*/ "ujis COLLATE ujis_japanese_ci",
    /*13*/ "sjis COLLATE sjis_japanese_ci",
    /*14*/ "cp1251 COLLATE cp1251_bulgarian_ci",
    /*15*/ "latin1 COLLATE latin1_danish_ci",
    /*16*/ "hebrew COLLATE hebrew_general_ci",
    /*17*/ "Unknown",
    /*18*/ "tis620 COLLATE tis620_thai_ci",
    /*19*/ "euckr COLLATE euckr_korean_ci",
    /*20*/ "latin7 COLLATE latin7_estonian_cs",
    /*21*/ "latin2 COLLATE latin2_hungarian_ci",
    /*22*/ "koi8u COLLATE koi8u_general_ci",
    /*23*/ "cp1251 COLLATE cp1251_ukrainian_ci",
    /*24*/ "gb2312 COLLATE gb2312_chinese_ci",
    /*25*/ "greek COLLATE greek_general_ci",
    /*26*/ "cp1250 COLLATE cp1250_general_ci",
    /*27*/ "latin2 COLLATE latin2_croatian_ci",
    /*28*/ "gbk COLLATE gbk_chinese_ci",
    /*29*/ "cp1257 COLLATE cp1257_lithuanian_ci",
    /*30*/ "latin5 COLLATE latin5_turkish_ci",
    /*31*/ "latin1 COLLATE latin1_german2_ci",
    /*32*/ "armscii8 COLLATE armscii8_general_ci",
    /*33*/ "utf8 COLLATE utf8_general_ci",
    /*34*/ "cp1250 COLLATE cp1250_czech_cs",
    /*35*/ "ucs2 COLLATE ucs2_general_ci",
    /*36*/ "cp866 COLLATE cp866_general_ci",
    /*37*/ "keybcs2 COLLATE keybcs2_general_ci",
    /*38*/ "macce COLLATE macce_general_ci",
    /*39*/ "macroman COLLATE macroman_general_ci",
    /*40*/ "cp852 COLLATE cp852_general_ci",
    /*41*/ "latin7 COLLATE latin7_general_ci",
    /*42*/ "latin7 COLLATE latin7_general_cs",
    /*43*/ "macce COLLATE macce_bin",
    /*44*/ "cp1250 COLLATE cp1250_croatian_ci",
    /*45*/ "utf8mb4 COLLATE utf8mb4_general_ci",
    /*46*/ "utf8mb4 COLLATE utf8mb4_bin",
    /*47*/ "latin1 COLLATE latin1_bin",
    /*48*/ "latin1 COLLATE latin1_general_ci",
    /*49*/ "latin1 COLLATE latin1_general_cs",
    /*50*/ "cp1251 COLLATE cp1251_bin",
    /*51*/ "cp1251 COLLATE cp1251_general_ci",
    /*52*/ "cp1251 COLLATE cp1251_general_cs",
    /*53*/ "macroman COLLATE macroman_bin",
    /*54*/ "utf16 COLLATE utf16_general_ci",
    /*55*/ "utf16 COLLATE utf16_bin",
    /*56*/ "utf16le COLLATE utf16le_general_ci",
    /*57*/ "cp1256 COLLATE cp1256_general_ci",
    /*58*/ "cp1257 COLLATE cp1257_bin",
    /*59*/ "cp1257 COLLATE cp1257_general_ci",
    /*60*/ "utf32 COLLATE utf32_general_ci",
    /*61*/ "utf32 COLLATE utf32_bin",
    /*62*/ "utf16le COLLATE utf16le_bin",
    /*63*/ "binary COLLATE binary",
    /*64*/ "armscii8 COLLATE armscii8_bin",
    /*65*/ "ascii COLLATE ascii_bin",
    /*66*/ "cp1250 COLLATE cp1250_bin",
    /*67*/ "cp1256 COLLATE cp1256_bin",
    /*68*/ "cp866 COLLATE cp866_bin",
    /*69*/ "dec8 COLLATE dec8_bin",
    /*70*/ "greek COLLATE greek_bin",
    /*71*/ "hebrew COLLATE hebrew_bin",
    /*72*/ "hp8 COLLATE hp8_bin",
    /*73*/ "keybcs2 COLLATE keybcs2_bin",
    /*74*/ "koi8r COLLATE koi8r_bin",
    /*75*/ "koi8u COLLATE koi8u_bin",
    /*76*/ "Unknown",
    /*77*/ "latin2 COLLATE latin2_bin",
    /*78*/ "latin5 COLLATE latin5_bin",
    /*79*/ "latin7 COLLATE latin7_bin",
    /*80*/ "cp850 COLLATE cp850_bin",
    /*81*/ "cp852 COLLATE cp852_bin",
    /*82*/ "swe7 COLLATE swe7_bin",
    /*83*/ "utf8 COLLATE utf8_bin",
    /*84*/ "big5 COLLATE big5_bin",
    /*85*/ "euckr COLLATE euckr_bin",
    /*86*/ "gb2312 COLLATE gb2312_bin",
    /*87*/ "gbk COLLATE gbk_bin",
    /*88*/ "sjis COLLATE sjis_bin",
    /*89*/ "tis620 COLLATE tis620_bin",
    /*90*/ "ucs2 COLLATE ucs2_bin",
    /*91*/ "ujis COLLATE ujis_bin",
    /*92*/ "geostd8 COLLATE geostd8_general_ci",
    /*93*/ "geostd8 COLLATE geostd8_bin",
    /*94*/ "latin1 COLLATE latin1_spanish_ci",
    /*95*/ "cp932 COLLATE cp932_japanese_ci",
    /*96*/ "cp932 COLLATE cp932_bin",
    /*97*/ "eucjpms COLLATE eucjpms_japanese_ci",
    /*98*/ "eucjpms COLLATE eucjpms_bin",
    /*99*/ "cp1250 COLLATE cp1250_polish_ci",
    /*100*/ "Unknown",
    /*101*/ "utf16 COLLATE utf16_unicode_ci",
    /*102*/ "utf16 COLLATE utf16_icelandic_ci",
    /*103*/ "utf16 COLLATE utf16_latvian_ci",
    /*104*/ "utf16 COLLATE utf16_romanian_ci",
    /*105*/ "utf16 COLLATE utf16_slovenian_ci",
    /*106*/ "utf16 COLLATE utf16_polish_ci",
    /*107*/ "utf16 COLLATE utf16_estonian_ci",
    /*108*/ "utf16 COLLATE utf16_spanish_ci",
    /*109*/ "utf16 COLLATE utf16_swedish_ci",
    /*110*/ "utf16 COLLATE utf16_turkish_ci",
    /*111*/ "utf16 COLLATE utf16_czech_ci",
    /*112*/ "utf16 COLLATE utf16_danish_ci",
    /*113*/ "utf16 COLLATE utf16_lithuanian_ci",
    /*114*/ "utf16 COLLATE utf16_slovak_ci",
    /*115*/ "utf16 COLLATE utf16_spanish2_ci",
    /*116*/ "utf16 COLLATE utf16_roman_ci",
    /*117*/ "utf16 COLLATE utf16_persian_ci",
    /*118*/ "utf16 COLLATE utf16_esperanto_ci",
    /*119*/ "utf16 COLLATE utf16_hungarian_ci",
    /*120*/ "utf16 COLLATE utf16_sinhala_ci",
    /*121*/ "utf16 COLLATE utf16_german2_ci",
    /*122*/ "utf16 COLLATE utf16_croatian_ci",
    /*123*/ "utf16 COLLATE utf16_unicode_520_ci",
    /*124*/ "utf16 COLLATE utf16_vietnamese_ci",
    /*125*/ "Unknown",
    /*126*/ "Unknown",
    /*127*/ "Unknown",
    /*128*/ "ucs2 COLLATE ucs2_unicode_ci",
    /*129*/ "ucs2 COLLATE ucs2_icelandic_ci",
    /*130*/ "ucs2 COLLATE ucs2_latvian_ci",
    /*131*/ "ucs2 COLLATE ucs2_romanian_ci",
    /*132*/ "ucs2 COLLATE ucs2_slovenian_ci",
    /*133*/ "ucs2 COLLATE ucs2_polish_ci",
    /*134*/ "ucs2 COLLATE ucs2_estonian_ci",
    /*135*/ "ucs2 COLLATE ucs2_spanish_ci",
    /*136*/ "ucs2 COLLATE ucs2_swedish_ci",
    /*137*/ "ucs2 COLLATE ucs2_turkish_ci",
    /*138*/ "ucs2 COLLATE ucs2_czech_ci",
    /*139*/ "ucs2 COLLATE ucs2_danish_ci",
    /*140*/ "ucs2 COLLATE ucs2_lithuanian_ci",
    /*141*/ "ucs2 COLLATE ucs2_slovak_ci",
    /*142*/ "ucs2 COLLATE ucs2_spanish2_ci",
    /*143*/ "ucs2 COLLATE ucs2_roman_ci",
    /*144*/ "ucs2 COLLATE ucs2_persian_ci",
    /*145*/ "ucs2 COLLATE ucs2_esperanto_ci",
    /*146*/ "ucs2 COLLATE ucs2_hungarian_ci",
    /*147*/ "ucs2 COLLATE ucs2_sinhala_ci",
    /*148*/ "ucs2 COLLATE ucs2_german2_ci",
    /*149*/ "ucs2 COLLATE ucs2_croatian_ci",
    /*150*/ "ucs2 COLLATE ucs2_unicode_520_ci",
    /*151*/ "ucs2 COLLATE ucs2_vietnamese_ci",
    /*152*/ "Unknown",
    /*153*/ "Unknown",
    /*154*/ "Unknown",
    /*155*/ "Unknown",
    /*156*/ "Unknown",
    /*157*/ "Unknown",
    /*158*/ "Unknown",
    /*159*/ "ucs2 COLLATE ucs2_general_mysql500_ci",
    /*160*/ "utf32 COLLATE utf32_unicode_ci",
    /*161*/ "utf32 COLLATE utf32_icelandic_ci",
    /*162*/ "utf32 COLLATE utf32_latvian_ci",
    /*163*/ "utf32 COLLATE utf32_romanian_ci",
    /*164*/ "utf32 COLLATE utf32_slovenian_ci",
    /*165*/ "utf32 COLLATE utf32_polish_ci",
    /*166*/ "utf32 COLLATE utf32_estonian_ci",
    /*167*/ "utf32 COLLATE utf32_spanish_ci",
    /*168*/ "utf32 COLLATE utf32_swedish_ci",
    /*169*/ "utf32 COLLATE utf32_turkish_ci",
    /*170*/ "utf32 COLLATE utf32_czech_ci",
    /*171*/ "utf32 COLLATE utf32_danish_ci",
    /*172*/ "utf32 COLLATE utf32_lithuanian_ci",
    /*173*/ "utf32 COLLATE utf32_slovak_ci",
    /*174*/ "utf32 COLLATE utf32_spanish2_ci",
    /*175*/ "utf32 COLLATE utf32_roman_ci",
    /*176*/ "utf32 COLLATE utf32_persian_ci",
    /*177*/ "utf32 COLLATE utf32_esperanto_ci",
    /*178*/ "utf32 COLLATE utf32_hungarian_ci",
    /*179*/ "utf32 COLLATE utf32_sinhala_ci",
    /*180*/ "utf32 COLLATE utf32_german2_ci",
    /*181*/ "utf32 COLLATE utf32_croatian_ci",
    /*182*/ "utf32 COLLATE utf32_unicode_520_ci",
    /*183*/ "utf32 COLLATE utf32_vietnamese_ci",
    /*184*/ "Unknown",
    /*185*/ "Unknown",
    /*186*/ "Unknown",
    /*187*/ "Unknown",
    /*188*/ "Unknown",
    /*189*/ "Unknown",
    /*190*/ "Unknown",
    /*191*/ "Unknown",
    /*192*/ "utf8 COLLATE utf8_unicode_ci",
    /*193*/ "utf8 COLLATE utf8_icelandic_ci",
    /*194*/ "utf8 COLLATE utf8_latvian_ci",
    /*195*/ "utf8 COLLATE utf8_romanian_ci",
    /*196*/ "utf8 COLLATE utf8_slovenian_ci",
    /*197*/ "utf8 COLLATE utf8_polish_ci",
    /*198*/ "utf8 COLLATE utf8_estonian_ci",
    /*199*/ "utf8 COLLATE utf8_spanish_ci",
    /*200*/ "utf8 COLLATE utf8_swedish_ci",
    /*201*/ "utf8 COLLATE utf8_turkish_ci",
    /*202*/ "utf8 COLLATE utf8_czech_ci",
    /*203*/ "utf8 COLLATE utf8_danish_ci",
    /*204*/ "utf8 COLLATE utf8_lithuanian_ci",
    /*205*/ "utf8 COLLATE utf8_slovak_ci",
    /*206*/ "utf8 COLLATE utf8_spanish2_ci",
    /*207*/ "utf8 COLLATE utf8_roman_ci",
    /*208*/ "utf8 COLLATE utf8_persian_ci",
    /*209*/ "utf8 COLLATE utf8_esperanto_ci",
    /*210*/ "utf8 COLLATE utf8_hungarian_ci",
    /*211*/ "utf8 COLLATE utf8_sinhala_ci",
    /*212*/ "utf8 COLLATE utf8_german2_ci",
    /*213*/ "utf8 COLLATE utf8_croatian_ci",
    /*214*/ "utf8 COLLATE utf8_unicode_520_ci",
    /*215*/ "utf8 COLLATE utf8_vietnamese_ci"};

static const struct val_str field_type_table[] = {
    {0x00, "FIELD_TYPE_DECIMAL"},
    {0x01, "FIELD_TYPE_TINY"},
    {0x02, "FIELD_TYPE_SHORT"},
    {0x03, "FIELD_TYPE_LONG"},
    {0x04, "FIELD_TYPE_FLOAT"},
    {0x05, "FIELD_TYPE_DOUBLE"},
    {0x06, "FIELD_TYPE_NULL"},
    {0x07, "FIELD_TYPE_TIMESTAMP"},
    {0x08, "FIELD_TYPE_LONGLONG"},
    {0x09, "FIELD_TYPE_INT24"},
    {0x0a, "FIELD_TYPE_DATE"},
    {0x0b, "FIELD_TYPE_TIME"},
    {0x0c, "FIELD_TYPE_DATETIME"},
    {0x0d, "FIELD_TYPE_YEAR"},
    {0x0e, "FIELD_TYPE_NEWDATE"},
    {0x0f, "FIELD_TYPE_VARCHAR"},
    {0x10, "FIELD_TYPE_BIT"},
    {0xf6, "FIELD_TYPE_NEWDECIMAL"},
    {0xf7, "FIELD_TYPE_ENUM"},
    {0xf8, "FIELD_TYPE_SET"},
    {0xf9, "FIELD_TYPE_TINY_BLOB"},
    {0xfa, "FIELD_TYPE_MEDIUM_BLOB"},
    {0xfb, "FIELD_TYPE_LONG_BLOB"},
    {0xfc, "FIELD_TYPE_BLOB"},
    {0xfd, "FIELD_TYPE_VAR_STRING"},
    {0xfe, "FIELD_TYPE_STRING"},
    {0xff, "FIELD_TYPE_GEOMETRY"},
    {0, NULL}};

typedef enum mysql_state {
    UNDEFINED,
    LOGIN,
    REQUEST,
    RESPONSE_OK,
    RESPONSE_MESSAGE,
    RESPONSE_TABULAR,
    RESPONSE_SHOW_FIELDS,
    FIELD_PACKET,
    ROW_PACKET,
    RESPONSE_PREPARE,
    PREPARED_PARAMETERS,
    PREPARED_FIELDS,
    AUTH_SWITCH_REQUEST,
    AUTH_SWITCH_RESPONSE
} mysql_state_t;

static const struct val_str mysql_state_table[] = {
    {UNDEFINED, "undefined"},
    {LOGIN, "login"},
    {REQUEST, "request"},
    {RESPONSE_OK, "response OK"},
    {RESPONSE_MESSAGE, "response message"},
    {RESPONSE_TABULAR, "tabular response"},
    {RESPONSE_SHOW_FIELDS, "response to SHOW FIELDS"},
    {FIELD_PACKET, "field packet"},
    {ROW_PACKET, "row packet"},
    {RESPONSE_PREPARE, "response to PREPARE"},
    {PREPARED_PARAMETERS, "parameters in response to PREPARE"},
    {PREPARED_FIELDS, "fields in response to PREPARE"},
    {AUTH_SWITCH_REQUEST, "authentication switch request"},
    {AUTH_SWITCH_RESPONSE, "authentication switch response"},
    {0, NULL}};

static const struct val_str mysql_exec_flags_table[] = {
    {MYSQL_CURSOR_TYPE_NO_CURSOR, "Defaults"},
    {MYSQL_CURSOR_TYPE_READ_ONLY, "Read-only cursor"},
    {MYSQL_CURSOR_TYPE_FOR_UPDATE, "Cursor for update"},
    {MYSQL_CURSOR_TYPE_SCROLLABLE, "Scrollable cursor"},
    {0, NULL}};

static const struct val_str mysql_new_parameter_bound_flag_vals[] = {
	{0, "Subsequent call"},
	{1, "First call or rebound"},
	{0, NULL}
};

static const struct val_str mysql_exec_time_sign_vals[] = {
	{0, "+"},
	{1, "_"},
	{0, NULL}
};

static const struct val_str mysql_shutdown_vals[] = {
	{0,   "default"},
	{1,   "wait for connections to finish"},
	{2,   "wait for transactions to finish"},
	{8,   "wait for updates to finish"},
	{16,  "wait flush all buffers"},
	{17,  "wait flush critical buffers"},
	{254, "kill running queries"},
	{255, "kill connections"},
	{0, NULL}
};

static const struct val_str mysql_option_vals[] = {
	{0, "multi statements on"},
	{1, "multi statements off"},
	{0, NULL}
};

static const struct val_str mysql_session_track_type_vals[] = {
	{0, "SESSION_SYSVARS_TRACKER"},
	{1, "CURRENT_SCHEMA_TRACKER"},
	{2, "SESSION_STATE_CHANGE_TRACKER"},
	{0, NULL}
};

static const struct val_str mysql_refresh_flag_table[] = {
    { MYSQL_RFSH_GRANT,     "reload permissions"},
	{ MYSQL_RFSH_LOG,       "flush logfiles"},
	{ MYSQL_RFSH_TABLES,    "flush tables"},
	{ MYSQL_RFSH_HOSTS,     "flush hosts"},
	{ MYSQL_RFSH_STATUS,    "reset statistics"},
	{ MYSQL_RFSH_THREADS,   "empty thread cache"},
	{ MYSQL_RFSH_SLAVE,     "flush slave status"},
	{ MYSQL_RFSH_MASTER,    "flush master status"},
	{0, NULL}
};

static const struct val_str mysql_caps_table[] = {
	{ MYSQL_CAPS_LP,    "Long Password"},
	{ MYSQL_CAPS_FR,    "Found Rows"},
	{ MYSQL_CAPS_LF,    "Long Column Flags"},
	{ MYSQL_CAPS_CD,    "Connect With Database"},
	{ MYSQL_CAPS_NS,    "Don't Allow database.table.column"},
	{ MYSQL_CAPS_CP,    "Can use compression protocol"},
	{ MYSQL_CAPS_OB,    "ODBC Client"},
	{ MYSQL_CAPS_LI,    "Can Use LOAD DATA LOCAL"},
	{ MYSQL_CAPS_IS,    "Ignore Spaces before '('"},
	{ MYSQL_CAPS_CU,    "Speaks 4.1 protocol (new flag)"},
	{ MYSQL_CAPS_IA,    "Interactive Client"},
	{ MYSQL_CAPS_SL,    "Switch to SSL after handshake"},
	{ MYSQL_CAPS_II,    "Ignore sigpipes"},
	{ MYSQL_CAPS_TA,    "Knows about transactions"},
	{ MYSQL_CAPS_RS,    "Speaks 4.1 protocol (old flag)"},
	{ MYSQL_CAPS_SC,    "Can do 4.1 authentication"},
    {0, NULL}
};

static const struct val_str mysql_ext_caps_table[] = {
    { MYSQL_CAPS_MS,    "Multiple statements"},
	{ MYSQL_CAPS_MR,    "Multiple results"},
	{ MYSQL_CAPS_PM,    "PS Multiple results"},
	{ MYSQL_CAPS_PA,    "Plugin Auth"},
	{ MYSQL_CAPS_CA,    "Connect attrs"},
	{ MYSQL_CAPS_AL,    "Plugin Auth LENENC Client Data"},
	{ MYSQL_CAPS_EP,    "Client can handle expired passwords"},
	{ MYSQL_CAPS_ST,    "Session variable tracking"},
	{ MYSQL_CAPS_DE,    "Deprecate EOF"},
	{ MYSQL_CAPS_UNUSED, "Unused"},
    {0, NULL}
};

static const struct val_str mysql_server_status_table[] = {
	{ MYSQL_STAT_IT,    "In transaction"},
	{ MYSQL_STAT_AC,    "AUTO_COMMIT"},
	{ MYSQL_STAT_MR,    "More results"},
	{ MYSQL_STAT_MU,    "Multi query - more resultsets"},
	{ MYSQL_STAT_BI,    "Bad index used"},
	{ MYSQL_STAT_NI,    "No index used"},
	{ MYSQL_STAT_CR,    "Cursor exists"},
	{ MYSQL_STAT_LR,    "Last row sent"},
	{ MYSQL_STAT_DR,    "database dropped"},
	{ MYSQL_STAT_BS,    "No backslash escapes"},
	{ MYSQL_STAT_SESSION_STATE_CHANGED, "Session state changed"},
	{ MYSQL_STAT_QUERY_WAS_SLOW,        "Query was slow"},
	{ MYSQL_STAT_PS_OUT_PARAMS,         "PS Out Params"},
    {0, NULL}
};

static const struct val_str mysql_field_flags_table[] = {
	{ MYSQL_FLD_NOT_NULL_FLAG,      "Not null"},
	{ MYSQL_FLD_PRI_KEY_FLAG,       "Primary key"},
	{ MYSQL_FLD_UNIQUE_KEY_FLAG,    "Unique key"},
	{ MYSQL_FLD_MULTIPLE_KEY_FLAG,  "Multiple key"},
	{ MYSQL_FLD_BLOB_FLAG,          "Blob"},
	{ MYSQL_FLD_UNSIGNED_FLAG,      "Unsigned"},
	{ MYSQL_FLD_ZEROFILL_FLAG,      "Zero fill"},
	{ MYSQL_FLD_BINARY_FLAG,        "Binary"},
	{ MYSQL_FLD_ENUM_FLAG,          "Enum"},
	{ MYSQL_FLD_AUTO_INCREMENT_FLAG,"Auto increment"},
	{ MYSQL_FLD_TIMESTAMP_FLAG,     "Timestamp"},
	{ MYSQL_FLD_SET_FLAG,           "Set"},
    {0, NULL}
};

static inline const char *
val_to_str(const struct val_str *val_strs, uint32_t val, char *def)
{
    struct val_str *p = (struct val_str *)val_strs - 1;
    while ((++p)->str)
    {
        if (p->val == val)
        {
            return p->str;
        }
    }
    return def;
}

// free result
static inline char *
val_flag_to_str(const struct val_str *val_strs, uint32_t val, char *def)
{
    struct buffer *buf = buf_create_ex(100, 0);
    struct val_str *p = (struct val_str *)val_strs - 1;
    while ((++p)->str)
    {
        if (p->val & val)
        {
			if (buf_readable(buf)) {
				buf_append(buf, "; ", 1);
			}
            buf_append(buf, p->str, strlen(p->str));
        }
    }
    char* ret = NULL; 
    if (buf_readable(buf)){
        ret = buf_dupStr(buf, buf_readable(buf));
    } else {
        ret = strdup(def);
    }
    buf_release(buf);
    return ret;
}

static inline const char *
mysql_get_command(uint32_t val, char *def)
{
    if (val >= sizeof(mysql_command_table))
    {
        return def;
    }
    return mysql_command_table[val];
}

static inline const char *
mysql_get_charset(uint32_t val, char *def)
{
    if (val >= sizeof(mysql_charset_table))
    {
        return def;
    }
    return mysql_charset_table[val];
}

static inline const char *
mysql_get_field_type(uint32_t val, char *def)
{
    return val_to_str(field_type_table, val, def);
}

static inline const char *
mysql_get_parameter_bound_val(uint32_t val, char *def)
{
    return val_to_str(mysql_new_parameter_bound_flag_vals, val, def);
}

static inline const char *
mysql_get_time_sign(uint32_t val, char *def)
{
    return val_to_str(mysql_exec_time_sign_vals, val, def);
}

static inline const char *
mysql_get_option_val(uint32_t val, char *def)
{
    return val_to_str(mysql_option_vals, val, def);
}

static inline const char *
mysql_get_session_track_type(uint32_t val, char *def)
{
    return val_to_str(mysql_session_track_type_vals, val, def);
}

// TODO 确认这里是按比位取值还是枚举
static inline const char *
mysql_get_shutdown_val(uint32_t val, char *def)
{
    return val_to_str(mysql_shutdown_vals, val, def);
}

// TODO 确认这里是按比位取值还是枚举
static inline const char *
mysql_get_exec_flags_val(uint8_t val, char *def)
{
    return val_to_str(mysql_exec_flags_table, val, def);
}

static inline const char *
mysql_get_static_val(int8_t val, char *def)
{
    return val_to_str(mysql_state_table, val, def);
}

static inline char *
mysql_get_refresh_val(uint8_t val, char *def) {
    return val_flag_to_str(mysql_refresh_flag_table, val, def);
}

static inline char *
mysql_get_cap_val(uint16_t val, char *def) {
    return val_flag_to_str(mysql_caps_table, val, def);
}

static inline char *
mysql_get_ext_cap_val(uint16_t val, char *def) {
    if (val == 0) {
        return strdup("empty");
    }
    return val_flag_to_str(mysql_ext_caps_table, val, def);
}

static inline char *
mysql_get_server_status_val(uint16_t val, char *def) {
    return val_flag_to_str(mysql_server_status_table, val, def);
}

static inline char *
mysql_get_field_flags_val(uint16_t val, char *def) {
    return val_flag_to_str(mysql_field_flags_table, val, def);
}

#endif