#ifndef STORAGE_H
#define STORAGE_H

#include <Arduino.h>
#include <vector>
#include "types.h"

void loadConfiguration(std::vector<TOTPAccount> &accounts);
void saveConfiguration(const std::vector<TOTPAccount> &accounts);

#endif