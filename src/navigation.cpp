#include "navigation.h"
#include "auth_handler.h"
#include "app_config.h"
#include "../core/fido2/device.h"
#include <string.h>
#include "display_handler.h"
#include <Adafruit_SSD1306.h>
#include <Adafruit_TinyUSB.h>
#include "../core/fido2/ctaphid.h"

extern Adafruit_SSD1306 display;
static NavContext *_g_nav_ctx = nullptr;

extern "C" {
    extern volatile int8_t _fido_ui_request;
}

void nav_init(NavContext &ctx)
{
    _g_nav_ctx = &ctx;
    ctx.state = NAV_CLOCK;
    ctx.menuIndex = 0;
    ctx.accountIndex = 0;
    ctx.accountCount = 0;
    ctx.authErrorStartMs = 0;
    ctx.fidoStatusStartMs = 0;
}

void nav_update(NavContext &ctx, unsigned long nowMs)
{
    /* ── Auth error auto-return ── */
    if (ctx.state == NAV_AUTH_ERROR)
    {
        if (nowMs - ctx.authErrorStartMs >= (unsigned long)AUTH_ERROR_DISPLAY_MS)
        {
            ctx.state = NAV_CLOCK;
            auth_handler_clear();
        }
        return; /* no button handling during error display */
    }

    /* ── FIDO success auto-return ── */
    if (ctx.state == NAV_FIDO_SUCCESS)
    {
        if (nowMs - ctx.fidoStatusStartMs >= 2000)
        {
            ctx.state = NAV_CLOCK;
        }
        return;
    }

    /* ── Inactivity timeout on protected pages ── */
    if (ctx.state != NAV_CLOCK && ctx.state != NAV_AUTH_PROMPT && ctx.state != NAV_AUTH_ERROR && 
        ctx.state != NAV_FIDO_PROMPT && ctx.state != NAV_FIDO_PROCESSING && ctx.state != NAV_FIDO_SUCCESS)
    {
        if (auth_handler_check_inactivity(nowMs))
        {
            ctx.state = NAV_CLOCK;
            return;
        }
    }

    /* ── Read buttons (consumed on read) ── */
    int left   = device_button_pressed(BTN_LEFT);
    int center = device_button_pressed(BTN_CENTER);
    int right  = device_button_pressed(BTN_RIGHT);

    // ── Aggressive FIDO Takeover ──
    // If a FIDO request is active, force the state and bypass normal navigation
    if (_fido_ui_request == 1) {
        ctx.state = NAV_FIDO_PROMPT;
    } else if (_fido_ui_request == 2) {
        ctx.state = NAV_FIDO_PROCESSING;
    }

    if (!left && !center && !right)
        return;

    /* ── State machine ── */
    switch (ctx.state)
    {
    case NAV_CLOCK:
        if (center)
        {
            ctx.state = NAV_MENU;
            ctx.menuIndex = 0;
        }
        break;

    case NAV_MENU:
        if (right)
        {
            ctx.menuIndex = (ctx.menuIndex + 1) % MENU_ITEM_COUNT;
        }
        else if (left)
        {
            ctx.state = NAV_CLOCK;
        }
        else if (center)
        {
            switch (ctx.menuIndex)
            {
            case MENU_TOTP:
                if (auth_handler_needs_auth())
                {
                    ctx.state = NAV_AUTH_PROMPT;
                }
                else
                {
                    ctx.state = NAV_TOTP_VIEW;
                    ctx.accountIndex = 0;
                    auth_handler_record_activity(nowMs);
                }
                break;
            case MENU_SETTINGS:
                ctx.state = NAV_SETTINGS;
                auth_handler_record_activity(nowMs);
                break;
            default:
                break;
            }
        }
        break;

    case NAV_TOTP_VIEW:
        auth_handler_record_activity(nowMs);
        if (right)
        {
            if (ctx.accountCount > 0)
                ctx.accountIndex = (ctx.accountIndex + 1) % ctx.accountCount;
        }
        else if (left)
        {
            ctx.state = NAV_MENU;
        }
        break;

    case NAV_SETTINGS:
        auth_handler_record_activity(nowMs);
        if (left)
        {
            ctx.state = NAV_MENU;
        }
        /* right / center reserved for future setting items */
        break;

    case NAV_AUTH_PROMPT:
        if (center || left)
        {
            ctx.state = NAV_CLOCK;
            auth_handler_clear();
        }
        break;

    case NAV_FIDO_PROMPT:
        if (center)
        {
            /* User confirmed presence */
            ctaphid_confirm_user_presence();
            ctx.state = NAV_FIDO_PROCESSING;
        }
        else if (left)
        {
            /* User cancelled */
            ctaphid_cancel_request();
            ctx.state = NAV_CLOCK;
        }
        break;

    default:
        break;
    }
}

/** 
 * Non-blocking User Presence check for CTAP2.
 */
static bool _up_confirmed = false;

void dev_fido_signal_up() { _up_confirmed = true; }

bool device_fido_check_user_presence(bool consume) {
    bool val = _up_confirmed;
    if (consume) _up_confirmed = false;
    return val;
}


void nav_auth_success(NavContext &ctx, unsigned long nowMs)
{
    if (ctx.state != NAV_AUTH_PROMPT)
        return;
    auth_handler_set_authenticated(true);
    ctx.state = NAV_TOTP_VIEW;
    ctx.accountIndex = 0;
    auth_handler_record_activity(nowMs);
}

void nav_auth_failed(NavContext &ctx, unsigned long nowMs)
{
    if (ctx.state != NAV_AUTH_PROMPT)
        return;
    ctx.state = NAV_AUTH_ERROR;
    ctx.authErrorStartMs = nowMs;
    auth_handler_verify_failed();
}

extern "C" {
void nav_set_state_fido_prompt() {
    if (_g_nav_ctx) {
        _g_nav_ctx->state = NAV_FIDO_PROMPT;
        strncpy(_g_nav_ctx->fidoRpId, "FIDO2 Operation", 63); // Generic for now
    }
}

void nav_set_state_fido_processing() {
    if (_g_nav_ctx) _g_nav_ctx->state = NAV_FIDO_PROCESSING;
}

void nav_set_state_clock() {
    if (_g_nav_ctx) _g_nav_ctx->state = NAV_CLOCK;
}
}
