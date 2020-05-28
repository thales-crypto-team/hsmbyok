/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMCONFIG_H
#define _HSMCONFIG_H

#include "HsmDefs.h"

//
// HsmConfig interface
//
// options for hsmbyok application
//

class HsmConfig {
public:
    static CK_RV InitFromIniFile(const char *fileName, const char *sectionName);
    static void ClearSensitiveParams();

    static bool WantCipher(const char *cipherName);
    static bool WantWrapMethod1();
    static bool WantSecretKeyTarget();
    static bool WantKeyPairTarget();

#if defined(LUNA_HAVE_MASTER_KEY)
public:
    static bool WantSecretKeyUnwrapped();
    static bool WantKeyPairUnwrapped();
#endif // LUNA_HAVE_MASTER_KEY

private:
    static int ReadIniKeySpec(CK_KEY_SPEC &spec, const char *fileName, const char *sectionName,
                                const char *valueName);
    static int ReadIniKeyFlags(CK_FLAGS &flags, const char *fileName, const char *sectionName, const char *valueName);

// FIXME: should be private
public:
    static char libraryName[CK_MAX_STRING_BYTES];
    static char tokenLabel[32 + 1];
    static char cryptoOfficerPin[CK_MAX_PIN_BYTES];
    static char wrappingCiphers[CK_MAX_STRING_BYTES];

    static char SchemaVersion[CK_MAX_STRING_BYTES];
    static char kid[CK_MAX_STRING_BYTES];

    static char targetKeyName[CK_MAX_LABEL_BYTES];
    static CK_KEY_SPEC targetKeySpec;
    static CK_FLAGS targetKeyFlags;

#if defined(LUNA_HAVE_MASTER_KEY)
// FIXME: should be private
public:
    static char masterKeyName[CK_MAX_LABEL_BYTES];
    static CK_KEY_SPEC masterKeySpec;
    static CK_FLAGS masterKeyFlags;

    static char unwrappedKeyName[CK_MAX_LABEL_BYTES];
    static CK_KEY_SPEC unwrappedKeySpec;
    static CK_FLAGS unwrappedKeyFlags;
#endif // LUNA_HAVE_MASTER_KEY

};

#endif // _HSMCONFIG_H
