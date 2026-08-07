#ifndef CORE_PIV_H
#define CORE_PIV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** NIST SP 800-73 PIV AID */
#define PIV_AID_LEN 11

/** Handle a single ISO7816 APDU. Returns response length written to out (includes SW). */
int piv_handle_apdu(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t out_max);

#ifdef __cplusplus
}
#endif

#endif
