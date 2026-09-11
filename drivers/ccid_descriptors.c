#include "ccid_descriptors.h"

static const uint8_t _template[CCID_DESC_TOTAL_LEN] = CCID_DESCRIPTOR_TEMPLATE;

const uint8_t *ccid_descriptor_template(size_t *len)
{
    if (len)
        *len = sizeof(_template);
    return _template;
}
