#include "navigation.h"
#include "auth_handler.h"
#include "../core/device.h"

void handleNavigation(PageEnum &currentPage, int &accountIndex, int accountCount, unsigned long currentTimeMs)
{
    if (!device_button_state())
        return;

    if (currentPage == PAGE_CLOCK)
    {
        currentPage = auth_handler_page_to_show(PAGE_TOTP);
        accountIndex = 0;
        auth_handler_record_activity(currentTimeMs);
    }
    else if (currentPage == PAGE_AUTH_PROMPT)
    {
        currentPage = PAGE_CLOCK;
    }
    else if (currentPage == PAGE_TOTP)
    {
        auth_handler_record_activity(currentTimeMs);
        if (accountCount > 1)
        {
            accountIndex++;
            if (accountIndex >= accountCount)
            {
                currentPage = PAGE_CLOCK;
                accountIndex = 0;
            }
        }
        else
        {
            currentPage = PAGE_CLOCK;
            accountIndex = 0;
        }
    }
    else if (currentPage == PAGE_SETTINGS)
    {
        auth_handler_record_activity(currentTimeMs);
        currentPage = PAGE_CLOCK;
    }
}
