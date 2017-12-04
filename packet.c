#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include "mysql_sniff.h"
#include "../base/buffer.h"
#include "../base/endian.h"


/* decoding table: exec_flags */
static const value_string mysql_exec_flags_vals[] = {
	{MYSQL_CURSOR_TYPE_NO_CURSOR, "Defaults"},
	{MYSQL_CURSOR_TYPE_READ_ONLY, "Read-only cursor"},
	{MYSQL_CURSOR_TYPE_FOR_UPDATE, "Cursor for update"},
	{MYSQL_CURSOR_TYPE_SCROLLABLE, "Scrollable cursor"},
	{0, NULL}
};

/* decoding table: new_parameter_bound_flag */
static const value_string mysql_new_parameter_bound_flag_vals[] = {
	{0, "Subsequent call"},
	{1, "First call or rebound"},
	{0, NULL}
};

/* decoding table: exec_time_sign */
static const value_string mysql_exec_time_sign_vals[] = {
	{0, "Positive"},
	{1, "Negative"},
	{0, NULL}
};


/* allowed MYSQL_SHUTDOWN levels */
static const value_string mysql_shutdown_vals[] = {
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


/* allowed MYSQL_SET_OPTION values */
static const value_string mysql_option_vals[] = {
	{0, "multi statements on"},
	{1, "multi statements off"},
	{0, NULL}
};

static const value_string mysql_session_track_type_vals[] = {
	{0, "SESSION_SYSVARS_TRACKER"},
	{1, "CURRENT_SCHEMA_TRACKER"},
	{2, "SESSION_STATE_CHANGE_TRACKER"},
	{0, NULL}
};



