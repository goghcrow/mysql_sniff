#ifndef MYSQL_LOG_H
#define MYSQL_LOG_H

enum LOG_LEVEL
{
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
};
void mysql_log(int level, const char *fmt, ...);


#define LOG_TRACE(...) mysql_log(LOG_TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) mysql_log(LOG_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) mysql_log(LOG_INFO, __VA_ARGS__)
#define LOG_WARN(...) mysql_log(LOG_WARN, __VA_ARGS__)
#define LOG_ERROR(...) mysql_log(LOG_ERROR, __VA_ARGS__)
#define LOG_FATAL(...) mysql_log(LOG_FATAL, __VA_ARGS__)


#endif