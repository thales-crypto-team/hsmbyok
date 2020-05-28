/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMSECRETKEY_H
#define _HSMSECRETKEY_H

#include "HsmKey.h"
#include "HsmUtils.h"
#include "HsmDefs.h"

class HsmKeyPair;

class HsmSecretKey : public HsmKey {
public:
    HsmSecretKey();
    virtual ~HsmSecretKey();

    // unsafe copy constructor, assignment operator
    HsmSecretKey(HsmSecretKey &) { HSM_BUG(""); }
    HsmSecretKey &operator=(HsmSecretKey &) { HSM_BUG(""); }

public:
    virtual CK_OBJECT_HANDLE GetKeyHandle() const { return GetSecretKeyHandle(); }
    virtual void ZeroizeHandles();
    virtual void ReportStatus(const char *pre, CK_RV rv) const;
    virtual CK_RV EncryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const;
    virtual CK_RV DecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const;

public:
    CK_OBJECT_HANDLE GetSecretKeyHandle() const { return hSecretObject; }
    CK_OBJECT_HANDLE GetWrappingKeyHandle() const { return GetSecretKeyHandle(); }
    CK_OBJECT_HANDLE GetUnwrappingKeyHandle() const { return GetSecretKeyHandle(); }

public:
    CK_RV LoadSecretKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_RV FindSecretKey(CK_SESSION_HANDLE hSession, std::string label);
    CK_RV GenerateSecretKey(CK_SESSION_HANDLE hSession, const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags);

public:
    CK_RV WrapKey(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const;
    CK_RV UnwrapKey(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob, const CK_KEY_SPEC &spec,
                    const std::string &label, CK_FLAGS ckflags) const;

public:
    static void SetSecretKeyTemplate(HsmTemplate &tplSecret, const CK_KEY_SPEC &spec, const std::string &label,
                                     CK_FLAGS ckflags);

private:
    CK_RV _EncryptDecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out, bool fDecrypt) const;

private:
    CK_OBJECT_HANDLE hSecretObject;
};

#endif // _HSMSECRETKEY_H
