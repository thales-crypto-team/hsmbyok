/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMKEYPAIR_H
#define _HSMKEYPAIR_H

#include "HsmKey.h"
#include "HsmUtils.h"
#include "HsmDefs.h"
#include <string>

class HsmSecretKey;

class HsmKeyPair : public HsmKey {
public:
    HsmKeyPair();
    virtual ~HsmKeyPair();

    // unsafe copy constructor, assignment operator
    HsmKeyPair(HsmKeyPair &) { HSM_BUG(""); }
    HsmKeyPair &operator=(HsmKeyPair &) { HSM_BUG(""); }

public:
    virtual CK_OBJECT_HANDLE GetKeyHandle() const { return GetPrivateKeyHandle(); }
    virtual void ZeroizeHandles();
    virtual void ReportStatus(const char *pre, CK_RV rv) const;
    virtual CK_RV EncryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const;
    virtual CK_RV DecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const;

public:
    CK_OBJECT_HANDLE GetPrivateKeyHandle() const { return hPrivateObject; }
    CK_OBJECT_HANDLE GetPublicKeyHandle() const { return hPublicObject; }
    CK_OBJECT_HANDLE GetWrappingKeyHandle() const { return GetPublicKeyHandle(); }
    CK_OBJECT_HANDLE GetUnwrappingKeyHandle() const { return GetPrivateKeyHandle(); }

public:
    CK_RV ImportPublicKey(CK_SESSION_HANDLE hSession, const HsmPublicKeyBlob *pblob);
    CK_RV ExportPublicKey(CK_SESSION_HANDLE hSession, HsmPublicKeyBlob **ppblob);
    CK_RV ImportPublicKey(CK_SESSION_HANDLE hSession, const std::string &pemfile);

public:
    CK_RV LoadKeyPair(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrivate,
                      CK_OBJECT_HANDLE hPublic = CK_INVALID_OBJECT_HANDLE, bool flagCreatePublic = false);
    CK_RV FindKeyPair(CK_SESSION_HANDLE hSession, std::string label);
    CK_RV GenerateKeyPair(CK_SESSION_HANDLE hSession, const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags);

public:
    CK_RV WrapSecretKey(CK_SESSION_HANDLE hSession, const HsmSecretKey *sk, HsmWrappedKeyBlob **ppblob) const;
    CK_RV WrapKeyMethod1(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const;
    CK_RV WrapKeyMethod2(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const;
    CK_RV UnwrapSecretKey(CK_SESSION_HANDLE hSession, HsmSecretKey **ppsk, const HsmWrappedKeyBlob *pblob,
                          const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const;
    CK_RV UnwrapKeyMethod1(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob,
                           const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const;
    CK_RV UnwrapKeyMethod2(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob,
                           const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const;

public:
    static void SetPublicKeyTemplate(HsmTemplate &tplPublic, const CK_KEY_SPEC &spec, const std::string &label,
                                     CK_FLAGS ckflags);
    static void SetPrivateKeyTemplate(HsmTemplate &tplPrivate, const CK_KEY_SPEC &spec, const std::string &label,
                                      CK_FLAGS ckflags);

private:
    static CK_RV _SetOaepHashType(CK_RSA_PKCS_OAEP_PARAMS &oaepParams);
    CK_RV _EncryptDecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out, bool fDecrypt) const;

private:
    CK_OBJECT_HANDLE hPrivateObject;
    CK_OBJECT_HANDLE hPublicObject;

    // flattened version of the public key
    typedef struct kek_s {
        CK_UINT32 magic; // CKA_RSA_PUBLIC_BLOB or CKA_EC_PUBLIC_BLOB
        union {
            struct {
                CK_UINT32 expLen;
                CK_UINT32 modLen;
                CK_BYTE exp[CK_MAX_PUBLIC_EXPONENT_BYTES];
                CK_BYTE mod[CK_MAX_MODULUS_BYTES];
            } rsa;
            struct {
                CK_UINT32 paramsLen;
                CK_UINT32 pointLen;
                CK_BYTE params[CK_MAX_EC_PARAMS_BYTES];
                CK_BYTE point[CK_MAX_EC_POINT_BYTES];
            } ec;
        } u;
    } kek_t;
    kek_t kek;
};

#endif // _HSMKEYPAIR_H
