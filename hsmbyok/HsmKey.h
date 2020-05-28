/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMKEY_H
#define _HSMKEY_H

#include "HsmDefs.h"
#include "HsmUtils.h"

class HsmKey {
public:
    HsmKey()
        : hSharedSession(CK_INVALID_SESSION_HANDLE), keyType(CK_INVALID_KEY_TYPE),
          keySizeBits(CK_INVALID_KEY_SIZE_BITS) {}

    virtual ~HsmKey() {}

    // unsafe copy constructor, assignment operator
    HsmKey(HsmKey &) { HSM_BUG(""); }
    HsmKey &operator=(HsmKey &) { HSM_BUG(""); }

public:
    CK_SESSION_HANDLE GetSharedSessionHandle() const { return hSharedSession; }
    CK_KEY_TYPE GetKeyType() const { return keyType; }
    CK_KEY_TYPE GetKeySizeBits() const { return keySizeBits; }

public:
    virtual CK_OBJECT_HANDLE GetKeyHandle() const = 0;
    virtual void ZeroizeHandles() {
        hSharedSession = CK_INVALID_SESSION_HANDLE;
        keyType = CK_INVALID_KEY_TYPE;
        keySizeBits = CK_INVALID_KEY_SIZE_BITS;
    }
    virtual void ReportStatus(const char *pre, CK_RV rv) const = 0;
    virtual CK_RV EncryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const = 0;
    virtual CK_RV DecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const = 0;

protected:
    CK_SESSION_HANDLE hSharedSession;
    CK_KEY_TYPE keyType;
    CK_ULONG keySizeBits;
};

#endif // _HSMKEY_H
