/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMDEFS_H
#define _HSMDEFS_H

#include "RSA/cryptoki.h"

#if defined(WIN32) || defined(_WIN32)
#pragma pack(push, HsmDefs, 1)
#endif

/****************************************************************************/

/*
 * cryptoki extensions for recommended wrapping mechanism (method1).
 * CKM_RSA_AES_KEY_WRAP (ie CKM_RSA_PKCS_OAEP + CKM_AES_KEY_WRAP_KWP
 * according to the latest pkcs11 spec).
 */

#define CKM_RSA_AES_KEY_WRAP 0x00001054

typedef struct CK_RSA_AES_KEY_WRAP_PARAMS {
    CK_ULONG ulAESKeyBits;
    CK_RSA_PKCS_OAEP_PARAMS_PTR pOAEPParams;
} CK_RSA_AES_KEY_WRAP_PARAMS;

/*
 * cryptoki extensions for alternate wrapping mechanisms (method2)
 * CKM_AES_KEY_WRAP_KWP or CKM_AES_KWP
 */

/* CKM_AES_KEY_WRAP_KWP complies with RFC5649 */
#define CKM_AES_KEY_WRAP_KWP 0x0000210B

/* Luna CKM_AES_KWP is identical to CKM_AES_KEY_WRAP_KWP */
#define CKM_AES_KWP (CKM_VENDOR_DEFINED + 0x171)

/* Avoid these mechanisms */
#undef CKM_AES_KEY_WRAP
#undef CKM_AES_KEY_WRAP_PAD
#undef CKM_AES_KW

/*
 * misc cryptoki extensions
 */

#define CK_INVALID_SESSION_HANDLE 0UL
#define CK_INVALID_OBJECT_HANDLE 0UL
#define CK_INVALID_KEY_TYPE (~0UL)
#define CK_INVALID_KEY_SIZE_BITS 0UL
#define CK_INVALID_SLOT_ID (~0UL)
#define CK_INVALID_MODULUS_BITS 0UL
#define CK_INVALID_TYPE (~0UL)
#define CK_INVALID_VALUE_LEN (~0UL)

#define CK_MAX_BYTES_FROM_BITS(_bits) (((_bits) + 7) / 8)
#define CK_MAX_MODULUS_BITS 8192
#define CK_MAX_MODULUS_BYTES CK_MAX_BYTES_FROM_BITS(CK_MAX_MODULUS_BITS)
#define CK_MAX_PUBLIC_EXPONENT_BYTES 128
#define CK_MAX_EC_KEY_BITS 521
#define CK_MAX_EC_POINT_BYTES 1024
#define CK_MAX_EC_PARAMS_BYTES 128

#define CK_MAX_LABEL_BYTES 256
#define CK_MAX_VALUE_BYTES 1024
#define CK_MAX_PIN_BYTES 256
#define CK_MAX_STRING_BYTES 256

#define CKF_EXTENSION 0x80000000
#define CKF_TOKEN 0x40000000
#define CKF_MODIFIABLE 0x20000000
#define CKF_EXTRACTABLE 0x10000000
#define CKF_CREATE_IF_NOT_FOUND 0x08000000

#define BYOK_CKA_BASE 0x8000F000
#define CKA_WRAPPED_KEY_BLOB (BYOK_CKA_BASE + 0x000)
#define CKA_PUBLIC_KEY_BLOB (BYOK_CKA_BASE + 0x001)
#define CKA_RSA_PUBLIC_BLOB (BYOK_CKA_BASE + 0x002)
#define CKA_EC_PUBLIC_BLOB (BYOK_CKA_BASE + 0x003)

#define BYOK_CKR_BASE 0x8000E000
#define CKR_OBJECT_NOT_FOUND (BYOK_CKR_BASE + 0x000)
#define CKR_LOAD_LIBRARY (BYOK_CKR_BASE + 0x001)
#define CKR_LOAD_LIBRARY_SYMBOL (BYOK_CKR_BASE + 0x002)
#define CKR_FILE_NOT_FOUND (BYOK_CKR_BASE + 0x003)
#define CKR_FILE_IO (BYOK_CKR_BASE + 0x004)
#define CKR_INVALID_COMMAND (BYOK_CKR_BASE + 0x005)
#define CKR_MULTIPLE_OBJECTS (BYOK_CKR_BASE + 0x006)
#define CKR_ZERO_SLOTS (BYOK_CKR_BASE + 0x007)
#define CKR_TOKEN_NOT_FOUND (BYOK_CKR_BASE + 0x008)
#define CKR_OBJECT_EXISTS (BYOK_CKR_BASE + 0x009)

typedef unsigned int CK_UINT32;

typedef struct _CK_KEY_SPEC {
    CK_KEY_TYPE keyType;
    CK_ULONG keySizeBits;
    const char *curveName; /* to distinguish EC curves */
} CK_KEY_SPEC;

/****************************************************************************/

#if defined(WIN32) || defined(_WIN32)
#pragma pack(pop, HsmDefs)
#endif

#endif /* _HSMDEFS_H */
