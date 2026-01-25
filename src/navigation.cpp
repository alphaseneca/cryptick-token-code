#include "navigation.h"
#include "config.h"

void handleNavigation(PageType &currentPage, int &accountIndex,
                      int accountCount, int buttonPin)
{
    static bool lastState = HIGH;
    static unsigned long lastPress = 0;

    bool currentState = digitalRead(buttonPin);

    if (lastState == HIGH && currentState == LOW)
    {
        if (millis() - lastPress > BUTTON_DEBOUNCE_MS)
        {
            lastPress = millis();

            if (currentPage == PAGE_CLOCK)
            {
                currentPage = PAGE_TOTP;
                accountIndex = 0;
            }
            else if (currentPage == PAGE_TOTP)
            {
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
        }
    }

    lastState = currentState;
}