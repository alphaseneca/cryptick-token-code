#include "credential_store.h"
#include <Arduino.h>

static SemaphoreHandle_t _mutex = NULL;

void credential_store_init(void)
{
    if (!_mutex)
        _mutex = xSemaphoreCreateRecursiveMutex();
}

void credential_store_lock(void)
{
    if (!_mutex)
        credential_store_init();
    if (_mutex)
        xSemaphoreTakeRecursive(_mutex, portMAX_DELAY);
}

void credential_store_unlock(void)
{
    if (_mutex)
        xSemaphoreGiveRecursive(_mutex);
}
