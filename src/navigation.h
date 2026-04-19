#ifndef NAVIGATION_H
#define NAVIGATION_H

/** Navigation states — hierarchical menu system. */
enum NavState
{
    NAV_CLOCK = 0,       /* Home screen (time display) */
    NAV_MENU,            /* Page menu — scroll with Right, enter with Center */
    NAV_TOTP_VIEW,       /* Inside TOTP — viewing accounts */
    NAV_SETTINGS,        /* Inside Settings page */
    NAV_AUTH_PROMPT,     /* Waiting for fingerprint verification */
    NAV_AUTH_ERROR,      /* Auth failed — auto-returns to clock */
    NAV_FIDO_PROMPT,     /* FIDO: "Tap to authenticate" */
    NAV_FIDO_PROCESSING, /* FIDO: Crypto in progress */
    NAV_FIDO_SUCCESS,    /* FIDO: Success indicator */
    NAV_STATE_COUNT
};

/** Menu page items. */
enum MenuItem
{
    MENU_TOTP = 0,
    MENU_SETTINGS = 1,
    MENU_ITEM_COUNT = 2
};

/** Navigation context — holds all navigation state. */
struct NavContext
{
    NavState state;
    int menuIndex;                  /* highlighted menu item */
    int accountIndex;               /* current TOTP account index */
    int accountCount;               /* total TOTP accounts (updated by main each loop) */
    unsigned long authErrorStartMs; /* timestamp when auth error began (for auto-return) */
    unsigned long fidoStatusStartMs; /* timestamp for FIDO success auto-return */
    char fidoRpId[64];              /* RP ID for the active prompt */
};

/** Initialize navigation context to clock state. */
void nav_init(NavContext &ctx);

/** Poll buttons and update navigation state. Call once per loop iteration. */
void nav_update(NavContext &ctx, unsigned long nowMs);

/** Called by main when fingerprint authentication succeeds. */
void nav_auth_success(NavContext &ctx, unsigned long nowMs);

/** Called by main when fingerprint authentication fails. */
void nav_auth_failed(NavContext &ctx, unsigned long nowMs);

#endif
