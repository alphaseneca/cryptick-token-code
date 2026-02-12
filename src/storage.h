#ifndef STORAGE_H
#define STORAGE_H

#include "../core/storage_hal.h"
#include <vector>

void loadConfiguration(std::vector<TOTPCredential> &credentials);
void saveConfiguration(const std::vector<TOTPCredential> &credentials);

#endif
