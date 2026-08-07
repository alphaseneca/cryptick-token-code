#ifndef CONFIG_H
#define CONFIG_H

#define SOLO_VERSION_MAJ 1
#define SOLO_VERSION_MIN 0
#define SOLO_VERSION_PATCH 0

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL 1
#endif

#define NFC_IS_ACTIVE 1
#define DEVICE_LOW_POWER_FAST 1
#define DEVICE_LOW_POWER_IDLE 0

#ifndef ENABLE_U2F
#define ENABLE_U2F
#endif
#ifndef ENABLE_CTAP2
#define ENABLE_CTAP2
#endif

#endif
