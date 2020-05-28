/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#include "HsmConfig.h"
#include "HsmUtils.h"
#include "HsmSys.h"

char HsmConfig::libraryName[CK_MAX_PIN_BYTES] = { 0 };
char HsmConfig::tokenLabel[32 + 1] = { 0 };
char HsmConfig::cryptoOfficerPin[CK_MAX_PIN_BYTES] = { 0 };
char HsmConfig::wrappingCiphers[CK_MAX_STRING_BYTES] = { 0 };

char HsmConfig::SchemaVersion[CK_MAX_STRING_BYTES];
char HsmConfig::kid[CK_MAX_STRING_BYTES];

char HsmConfig::targetKeyName[CK_MAX_LABEL_BYTES] = { 0 };
CK_KEY_SPEC HsmConfig::targetKeySpec = { CK_INVALID_KEY_TYPE, CK_INVALID_KEY_SIZE_BITS, 0 };
CK_ULONG HsmConfig::targetKeyFlags = 0;

#if defined(LUNA_HAVE_MASTER_KEY)
char HsmConfig::masterKeyName[CK_MAX_LABEL_BYTES] = { 0 };
CK_KEY_SPEC HsmConfig::masterKeySpec = { CK_INVALID_KEY_TYPE, CK_INVALID_KEY_SIZE_BITS, 0 };
CK_ULONG HsmConfig::masterKeyFlags = 0;

char HsmConfig::unwrappedKeyName[CK_MAX_LABEL_BYTES] = { 0 };
CK_KEY_SPEC HsmConfig::unwrappedKeySpec = { CK_INVALID_KEY_TYPE, CK_INVALID_KEY_SIZE_BITS, 0 };
CK_FLAGS HsmConfig::unwrappedKeyFlags = 0;
#endif

CK_RV HsmConfig::InitFromIniFile(const char *fileName, const char *sectionName) {
    if (HsmSys::ReadIni(libraryName, sizeof(libraryName), fileName, sectionName, "libraryName") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(tokenLabel, sizeof(tokenLabel), fileName, sectionName, "tokenLabel") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(wrappingCiphers, sizeof(wrappingCiphers), fileName, sectionName, "wrappingCiphers") <
        1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(SchemaVersion, sizeof(SchemaVersion), fileName, sectionName, "SchemaVersion") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(kid, sizeof(kid), fileName, sectionName, "kid") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(targetKeyName, sizeof(targetKeyName), fileName, sectionName, "targetKeyName") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeySpec(targetKeySpec, fileName, sectionName, "targetKeySpec") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeyFlags(targetKeyFlags, fileName, sectionName, "targetKeyFlags") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
#if defined(LUNA_HAVE_MASTER_KEY)
    if (HsmSys::ReadIni(masterKeyName, sizeof(masterKeyName), fileName, sectionName, "masterKeyName") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeySpec(masterKeySpec, fileName, sectionName, "masterKeySpec") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeyFlags(masterKeyFlags, fileName, sectionName, "masterKeyFlags") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmSys::ReadIni(unwrappedKeyName, sizeof(unwrappedKeyName), fileName, sectionName, "unwrappedKeyName") <
        1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeySpec(unwrappedKeySpec, fileName, sectionName, "unwrappedKeySpec") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
    if (HsmConfig::ReadIniKeyFlags(unwrappedKeyFlags, fileName, sectionName, "unwrappedKeyFlags") < 1) {
        return CKR_ARGUMENTS_BAD;
    }
#endif
    return CKR_OK;
}

void HsmConfig::ClearSensitiveParams() { memset(cryptoOfficerPin, 0, sizeof(cryptoOfficerPin)); }

bool HsmConfig::WantCipher(const char *cipherName) { return HsmSys::strcasestrrvalue(wrappingCiphers, cipherName) ? true : false; }

bool HsmConfig::WantWrapMethod1() { return WantCipher("CKM_RSA_AES_KEY_WRAP"); }

bool HsmConfig::WantSecretKeyTarget() { return HsmUtil::IsSecretKeyType(targetKeySpec.keyType); }

bool HsmConfig::WantKeyPairTarget() { return HsmUtil::IsKeyPairType(targetKeySpec.keyType); }

int HsmConfig::ReadIniKeySpec(CK_KEY_SPEC &spec, const char *fileName, const char *sectionName,
                                const char *valueName) {
    char tmp[CK_MAX_STRING_BYTES] = { 0 };
    char szKeyType[CK_MAX_STRING_BYTES] = { 0 };
    unsigned uKeySizeBits = 0;
    char szCurveName[CK_MAX_STRING_BYTES] = { 0 };
    if (HsmSys::ReadIni(tmp, sizeof(tmp), fileName, sectionName, valueName) < 1)
        return 0;
    char *saveptr = 0;
    char *tok = HsmSys::strtok_r(tmp, ":, \0", &saveptr);
    if (!tok)
        return 0;
    strcpy(szKeyType, tok);
    tok = HsmSys::strtok_r(NULL, ":, \0", &saveptr);
    if (!tok)
        return 0;
    uKeySizeBits = atoi(tok);
    tok = HsmSys::strtok_r(NULL, ":, \0", &saveptr);
    if (!tok)
        return 0;
    strcpy(szCurveName, tok);
    // set keyType
    spec.keyType = HsmUtil::KeyTypeFromString(szKeyType);
    if (spec.keyType == CK_INVALID_KEY_TYPE)
        return 0;
    // set keySizeBits
    spec.keySizeBits = uKeySizeBits;
    if (!spec.keySizeBits)
        return 0;
    // set curveName
    spec.curveName = strdup(szCurveName);
    if (!spec.curveName && spec.keyType == CKK_EC)
        return 0;
    HSM_INFO(("ReadIniKeySpec: keyType = 0x%08X, keySizeBits = %u, curveName = \"%s\"", (unsigned)spec.keyType,
              (unsigned)spec.keySizeBits, (spec.curveName ? spec.curveName : "(null)")));
    return 1;
}

int HsmConfig::ReadIniKeyFlags(CK_FLAGS &flags, const char *fileName, const char *sectionName,
                                 const char *valueName) {
    char tmp[CK_MAX_STRING_BYTES] = { 0 };
    if (HsmSys::ReadIni(tmp, sizeof(tmp), fileName, sectionName, valueName) < 1) {
        return 0;
    }
    if (HsmSys::strcasestrrvalue(tmp, "CKF_ENCRYPT"))
        flags |= CKF_ENCRYPT;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_DECRYPT"))
        flags |= CKF_DECRYPT;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_SIGN"))
        flags |= CKF_SIGN;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_SIGN_RECOVER"))
        flags |= CKF_SIGN_RECOVER;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_VERIFY"))
        flags |= CKF_VERIFY;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_VERIFY_RECOVER"))
        flags |= CKF_VERIFY_RECOVER;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_WRAP"))
        flags |= CKF_WRAP;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_UNWRAP"))
        flags |= CKF_UNWRAP;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_DERIVE"))
        flags |= CKF_DERIVE;
    // other keyFlags
    if (HsmSys::strcasestrrvalue(tmp, "CKF_EXTRACTABLE"))
        flags |= CKF_EXTRACTABLE;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_TOKEN"))
        flags |= CKF_TOKEN;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_MODIFIABLE"))
        flags |= CKF_MODIFIABLE;
    if (HsmSys::strcasestrrvalue(tmp, "CKF_CREATE_IF_NOT_FOUND"))
        flags |= CKF_CREATE_IF_NOT_FOUND;
    return 1;
}

#if defined(LUNA_HAVE_MASTER_KEY)
bool HsmConfig::WantSecretKeyUnwrapped() { return HsmUtil::IsSecretKeyType(unwrappedKeySpec.keyType); }

bool HsmConfig::WantKeyPairUnwrapped() { return HsmUtil::IsKeyPairType(unwrappedKeySpec.keyType); }
#endif // LUNA_HAVE_MASTER_KEY
