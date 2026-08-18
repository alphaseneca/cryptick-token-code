// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include "device.h"
#include "util.h"
#include "ctap.h"
#include "u2f.h"

#if defined(STUB_CTAPHID) || defined(STUB_CTAP)



void ctap_init()
{
    printf1(TAG_GEN,"STUB: ctap_init\n");
}
#endif

#if defined(STUB_CTAPHID)
void ctaphid_init()
{
    printf1(TAG_GEN,"STUB: ctaphid_init\n");
}
void ctaphid_handle_packet(uint8_t * hidmsg)
{
    printf1(TAG_GEN,"STUB: ctaphid_handle_packet\n");
}

void ctaphid_check_timeouts()
{

}

#endif


#ifdef STUB_CTAP

void ctap_reset_state()
{
    printf1(TAG_GEN,"STUB: ctap_reset_state\n");
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
}

void u2f_request(uint8_t *pkt, uint32_t len, CTAP_RESPONSE * resp)
{
    (void)pkt;
    (void)len;
    printf1(TAG_GEN,"STUB: u2f_request\n");
}

int u2f_last_was_presence_probe(void)
{
    return 0;
}

void ctap_uv_cache_arm_gettouch(void)
{
}

int ctap_user_presence_test_ex(uint32_t delay, int allow_uv_cache)
{
    (void)delay;
    (void)allow_uv_cache;
    return 1;
}

uint8_t ctap_request(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    printf1(TAG_GEN,"STUB: ctap_request\n");
    return 0;
}
#endif
