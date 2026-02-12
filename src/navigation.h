#ifndef NAVIGATION_H
#define NAVIGATION_H

enum PageEnum
{
    PAGE_CLOCK = 0,
    PAGE_TOTP = 1,
    PAGE_SETTINGS = 2,
    PAGE_AUTH_PROMPT = 3,
    PAGE_AUTH_ERROR = 4,
    PAGE_COUNT = 5
};

/** Update currentPage/accountIndex on button press. currentTimeMs = millis() from caller. Auth and activity are handled by auth_handler. */
void handleNavigation(PageEnum &currentPage, int &accountIndex, int accountCount, unsigned long currentTimeMs);

#endif
