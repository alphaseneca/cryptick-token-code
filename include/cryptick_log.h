/**
 * Cryptick unified CDC logging.
 *
 * Levels (higher includes lower):
 *   0 NONE  — silence (shipping default option)
 *   1 ERROR — failures only
 *   2 WARN  — recoverable issues
 *   3 INFO  — product milestones (boot, ready, enroll done)
 *   4 DEBUG — every subsystem action (default lab)
 *   5 TRACE — very chatty (HID pkts, poll, UI dirty, keepalives)
 *
 * Compile:
 *   -DCRYPTICK_LOG_LEVEL_DEFAULT=N
 * Ship: -DCRYPTICK_LOG_LEVEL_DEFAULT=1 -DDEBUG_LEVEL=0
 * Runtime: CDC  LOGLEVEL  /  LOG  0..5
 */
#ifndef CRYPTICK_LOG_H
#define CRYPTICK_LOG_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPTICK_LL_NONE = 0,
    CRYPTICK_LL_ERROR = 1,
    CRYPTICK_LL_WARN = 2,
    CRYPTICK_LL_INFO = 3,
    CRYPTICK_LL_DEBUG = 4,
    CRYPTICK_LL_TRACE = 5,
} cryptick_log_level_t;

#ifndef CRYPTICK_LOG_LEVEL_DEFAULT
#define CRYPTICK_LOG_LEVEL_DEFAULT CRYPTICK_LL_DEBUG
#endif

void cryptick_log_init(void);
void cryptick_log_set_level(cryptick_log_level_t level);
cryptick_log_level_t cryptick_log_get_level(void);
const char *cryptick_log_level_name(cryptick_log_level_t level);

/** printf-style; tag is short subsystem id, e.g. "BOOT", "FP", "IN". */
void cryptick_log(cryptick_log_level_t level, const char *tag, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

void cryptick_log_hex(cryptick_log_level_t level, const char *tag,
                      const uint8_t *data, size_t len);

/** Sink used by Solo FIDO log.c (fido_log_print). */
void cryptick_log_raw(const char *msg);

#define CLOG_E(tag, ...) cryptick_log(CRYPTICK_LL_ERROR, tag, __VA_ARGS__)
#define CLOG_W(tag, ...) cryptick_log(CRYPTICK_LL_WARN, tag, __VA_ARGS__)
#define CLOG_I(tag, ...) cryptick_log(CRYPTICK_LL_INFO, tag, __VA_ARGS__)
#define CLOG_D(tag, ...) cryptick_log(CRYPTICK_LL_DEBUG, tag, __VA_ARGS__)
#define CLOG_T(tag, ...) cryptick_log(CRYPTICK_LL_TRACE, tag, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* CRYPTICK_LOG_H */
