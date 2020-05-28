/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMSYS_H
#define _HSMSYS_H

//
// plaform specific definitions
//

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//
// HsmSys interface
//

class HsmSys {
public:
#if defined(_WIN32)
    typedef HMODULE HLIBRARY;
#else
    typedef void *HLIBRARY;
#endif

public:
    static HsmSys::HLIBRARY dlopen(const char *filename);
    static char *dlerror(void);
    static void *dlsym(HsmSys::HLIBRARY handle, const char *symbol);
    static void dlclose(HsmSys::HLIBRARY handle);

public:
    static const char *strcasestrrvalue(const char *haystack, const char *needle);
    static int strcasecmp(const char *s1, const char *s2);
    static char *strtok_r(char *str, const char *delim, char **saveptr);

public:
    static int ReadPassword(char *buffer, unsigned bufferLen);
    static int ReadIni(char *buffer, unsigned bufferLen, const char *fileName, const char *sectionName,
                               const char *valueName);
};

//
// misc macros
//

#define HSM_ERROR(_x) (printf("ERROR: "), ((printf _x), (printf("\n"))))
#define HSM_WARNING(_x) (printf("WARNING: "), ((printf _x), (printf("\n"))))
#define HSM_INFO(_x) (printf("INFO: "), ((printf _x), (printf("\n"))))
#define HSM_DEBUG(_x) (printf("DEBUG: "), ((printf _x), (printf("\n"))))

#define HSM_BUG(_msg) (fprintf(stderr, "BUG: %s: %u: %s.\n", __FILE__, __LINE__, (char *)(_msg)), exit(-1))
#define HSM_BUGX(_msg, _u32)                                                                                           \
    (fprintf(stderr, "BUG: %s: %u: %s: 0x%08X.\n", __FILE__, __LINE__, (char *)(_msg), (unsigned)(_u32)), exit(-1))
#define HSM_ASSERT(_expr)                                                                                              \
    ((!(_expr)) ? (fprintf(stderr, "ASSERT: %s: %u: %s.\n", __FILE__, __LINE__, #_expr), (exit(-1), -1)) : 0)

#ifndef DIM
#define DIM(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#ifndef MAX
#define MAX(_a, _b) (((_a) >= (_b)) ? (_a) : (_b))
#endif

#ifndef MIN
#define MIN(_a, _b) (((_a) <= (_b)) ? (_a) : (_b))
#endif

#if defined(_WIN32)
#define __HSM_FUNC__ __func__
#else
//#define __HSM_FUNC__ __PRETTY_FUNCTION__
//#define __HSM_FUNC__ __FUNCTION__
#define __HSM_FUNC__ __func__
#endif

#endif // _HSMSYS_H
