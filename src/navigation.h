#ifndef NAVIGATION_H
#define NAVIGATION_H

#include <Arduino.h>
#include "types.h"

void handleNavigation(PageType &currentPage, int &accountIndex,
                      int accountCount, int buttonPin);

#endif