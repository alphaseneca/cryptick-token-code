#include "version.h"

const version_t firmware_version
#ifdef SOLO
__attribute__ ((__used__))
#endif
    =  {
      .major = SOLO_VERSION_MAJ,
      .minor = SOLO_VERSION_MIN,
      .patch = SOLO_VERSION_PATCH,
      .reserved = 0
    };

/* Local assert — do not pull tinycbor compilersupport (file-scope macro issues). */
typedef char version_t_size_check[(sizeof(version_t) == 4) ? 1 : -1];
