#ifndef CORE_STORAGE_HAL_H
#define CORE_STORAGE_HAL_H

#include <stddef.h>
#include "totp.h"

/** Load TOTP credentials from persistent storage. *count set to loaded count. */
void storage_load_config(TOTPCredential *credentials, size_t max_count, size_t *count);

/** Save TOTP credentials to persistent storage. */
void storage_save_config(const TOTPCredential *credentials, size_t count);

#endif
