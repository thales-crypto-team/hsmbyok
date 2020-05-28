/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#include "HsmSecretKey.h"
#include "HsmKeyPair.h"
#include "HsmConfig.h"
#include "HsmUtils.h"

HsmSecretKey::HsmSecretKey() : hSecretObject(CK_INVALID_OBJECT_HANDLE) {}

HsmSecretKey::~HsmSecretKey() {}

void HsmSecretKey::ZeroizeHandles() {
    HsmKey::ZeroizeHandles();
    hSecretObject = CK_INVALID_OBJECT_HANDLE;
}

// load secret key details by object handle (usually a generated or unwrapped key handle)
CK_RV HsmSecretKey::LoadSecretKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_ULONG tmpKeyType = CK_INVALID_KEY_TYPE;
    CK_ULONG tmpValueLen = CK_INVALID_VALUE_LEN;

    // template to read the keytype, keysize
    CK_ATTRIBUTE _tplReadType[] = { { CKA_KEY_TYPE, &tmpKeyType, sizeof(tmpKeyType) },
                                    { CKA_VALUE_LEN, &tmpValueLen, sizeof(tmpValueLen) } };

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hSecretObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;
    hSecretObject = hObject;

    // C_GetAttributeValue
    rv = P11->C_GetAttributeValue(hSession, hSecretObject, _tplReadType, DIM(_tplReadType));

    if (rv == CKR_OK) {
        if (!HsmUtil::IsSecretKeyType(tmpKeyType)) {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // post-initialize
    if (rv == CKR_OK) {
        keyType = tmpKeyType;
        keySizeBits = (tmpValueLen * 8);
    }

    //ReportStatus("LoadSecretKey", rv);
    ReportStatus(__HSM_FUNC__, rv);
    return rv;
}

// find secret key by label and load key details
CK_RV HsmSecretKey::FindSecretKey(CK_SESSION_HANDLE hSession, std::string label) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    const CK_OBJECT_CLASS ckoSecret = CKO_SECRET_KEY;
    const CK_BBOOL bTrue = CK_TRUE;

    // template to find the private key
    CK_ATTRIBUTE _tplFind[] = { { CKA_CLASS, 0, 0 }, { CKA_TOKEN, 0, 0 }, { CKA_PRIVATE, 0, 0 }, { CKA_LABEL, 0, 0 } };

    HsmTemplate tplFind(_tplFind, DIM(_tplFind));

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hSecretObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;

    // initialize template
    tplFind.SetOnce(CKA_CLASS, ckoSecret);
    tplFind.SetOnce(CKA_TOKEN, bTrue);
    tplFind.SetOnce(CKA_PRIVATE, bTrue);
    tplFind.SetOnce(CKA_LABEL, label);

    // C_FindObjects
    rv = P11->C_FindObjectsInit(hSession, tplFind.c_array(), tplFind.c_count());
    if (rv == CKR_OK) {
        CK_OBJECT_HANDLE hFoundObjects[2] = { 0, 0 };
        CK_ULONG ulObjectCount = 0;
        HSM_ASSERT(DIM(hFoundObjects) >= 2);
        CK_RV rvfind = P11->C_FindObjects(hSession, hFoundObjects, DIM(hFoundObjects), &ulObjectCount);
        // the count must equal one; i.e., multiple secret keys cannot share the same label
        if (rvfind == CKR_OK) {
            if (ulObjectCount == 0) {
                rv = CKR_OBJECT_NOT_FOUND;
            } else if (ulObjectCount == 1) {
                hSecretObject = hFoundObjects[0];
                rv = CKR_OK;
            } else {
                rv = CKR_MULTIPLE_OBJECTS;
            }
        } else {
            rv = rvfind;
        }
        (void)P11->C_FindObjectsFinal(hSession);
    }

    // LoadSecretKey
    if (rv == CKR_OK) {
        const CK_OBJECT_HANDLE tmp_handle = hSecretObject;
        ZeroizeHandles(); // for LoadSecretKey that checks re-initialization
        rv = LoadSecretKey(hSession, tmp_handle);
    }

    return rv;
}

// generate a new secret key (symmetric)
CK_RV HsmSecretKey::GenerateSecretKey(CK_SESSION_HANDLE hSession, const CK_KEY_SPEC &spec, std::string label,
                                      CK_FLAGS ckflags) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechGen = { 0, 0, 0 };
    HsmTemplate tplGen;

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hSecretObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;
    keyType = spec.keyType;
    keySizeBits = spec.keySizeBits;
    if (spec.keyType == CKK_AES) {
        mechGen.mechanism = CKM_AES_KEY_GEN;
        rv = CKR_OK;
    } else if (spec.keyType == CKK_DES3) {
        mechGen.mechanism = CKM_DES3_KEY_GEN;
        rv = CKR_OK;
    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_GenerateKey
    if (rv == CKR_OK) {
        SetSecretKeyTemplate(tplGen, spec, label, ckflags);
        rv = P11->C_GenerateKey(hSession, &mechGen, tplGen.c_array(), tplGen.c_count(), &hSecretObject);
    }

    //ReportStatus("GenerateSecretKey", rv);
    ReportStatus(__HSM_FUNC__, rv);
    return rv;
}

// wrap any keyType with this secret key
CK_RV HsmSecretKey::WrapKey(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechWrap = { 0, 0, 0 };
    CK_BYTE_PTR pWrappedKey = 0;
    CK_ULONG ulWrappedKeyLen = 0;

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);
    HSM_ASSERT(hSession == key->GetSharedSessionHandle());

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_AES) {
        if (HsmConfig::WantCipher("CKM_AES_KEY_WRAP_KWP")) {
            mechWrap.mechanism = CKM_AES_KEY_WRAP_KWP;
            rv = CKR_OK;
        } else if (HsmConfig::WantCipher("CKM_AES_KWP")) {
            mechWrap.mechanism = CKM_AES_KWP;
            rv = CKR_OK;
        } else {
            rv = CKR_MECHANISM_INVALID;
        }
    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_WrapKey
    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, hSecretObject, key->GetKeyHandle(), NULL, &ulWrappedKeyLen);
    }

    if (rv == CKR_OK) {
        HSM_ASSERT(ulWrappedKeyLen);
        pWrappedKey = new CK_BYTE[ulWrappedKeyLen];
        HSM_ASSERT(pWrappedKey);
    }

    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, hSecretObject, key->GetKeyHandle(), pWrappedKey, &ulWrappedKeyLen);
    }

    if (rv == CKR_OK) {
        (*ppblob) = new HsmWrappedKeyBlob(pWrappedKey, ulWrappedKeyLen);
    }

    delete pWrappedKey;

    return rv;
}

// unwrap any keyType with this secret key
CK_RV HsmSecretKey::UnwrapKey(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob,
                              const CK_KEY_SPEC &spec, const std::string &label, CK_FLAGS ckflags) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechWrap = { 0, 0, 0 };
    HsmTemplate *pTemplate = new HsmTemplate;
    CK_OBJECT_HANDLE hObject = CK_INVALID_OBJECT_HANDLE;
    HsmKey *key = 0;

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_AES) {
        if (HsmConfig::WantCipher("CKM_AES_KEY_WRAP_KWP")) {
            mechWrap.mechanism = CKM_AES_KEY_WRAP_KWP;
            rv = CKR_OK;
        } else if (HsmConfig::WantCipher("CKM_AES_KWP")) {
            mechWrap.mechanism = CKM_AES_KWP;
            rv = CKR_OK;
        } else {
            rv = CKR_MECHANISM_INVALID;
        }
    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // initialize template
    if (rv == CKR_OK) {
        if (HsmUtil::IsSecretKeyType(spec.keyType)) {
            HsmSecretKey::SetSecretKeyTemplate(*pTemplate, spec, label, ckflags);
        } else if (HsmUtil::IsKeyPairType(spec.keyType)) {
            HsmKeyPair::SetPrivateKeyTemplate(*pTemplate, spec, label, ckflags);
        } else {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // C_UnwrapKey
    if (rv == CKR_OK) {
        rv = P11->C_UnwrapKey(hSession, &mechWrap, hSecretObject, pblob->c_value(), pblob->c_valueLen(),
                              pTemplate->c_array(), pTemplate->c_count(), &hObject);
    }

    // C_GetAttributeValue (CKA_KEY_TYPE)
    CK_ULONG tmpKeyType = CK_INVALID_KEY_TYPE;
    if (rv == CKR_OK) {
        CK_ATTRIBUTE _tplReadType[] = { { CKA_KEY_TYPE, &tmpKeyType, sizeof(tmpKeyType) } };
        rv = P11->C_GetAttributeValue(hSession, hObject, _tplReadType, DIM(_tplReadType));
    }

    // LoadKey
    if (rv == CKR_OK) {
        if (HsmUtil::IsSecretKeyType(tmpKeyType)) {
            HsmSecretKey *sk = new HsmSecretKey;
            rv = sk->LoadSecretKey(hSession, hObject);
            key = sk;
        } else if (HsmUtil::IsKeyPairType(tmpKeyType)) {
            HsmKeyPair *kp = new HsmKeyPair;
            rv = kp->LoadKeyPair(hSession, hObject);
            key = kp;
        } else {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }

        if (rv != CKR_OK) {
            // destroy unwrapped key on error
            (void)P11->C_DestroyObject(hSession, hObject);
            hObject = CK_INVALID_OBJECT_HANDLE;
            delete key;
            key = 0;
        }
    }

    if (rv == CKR_OK) {
        (*ppkey) = key; // take ownership of key
        key = 0;
    }

    delete pTemplate;
    delete key;

    return rv;
}

// set attribute template for generated or unwrapped secret key
void HsmSecretKey::SetSecretKeyTemplate(HsmTemplate &tplGen, const CK_KEY_SPEC &spec, const std::string &label,
                                        CK_FLAGS ckflags) {
    const CK_OBJECT_CLASS ckoSecret = CKO_SECRET_KEY;
    const CK_BBOOL bFalse = CK_FALSE;
    const CK_BBOOL bTrue = CK_TRUE;
    // Table 14
    tplGen.AppendOnce(CKA_CLASS, ckoSecret);
    // Table 18
    tplGen.AppendOnce(CKA_TOKEN, ckflags & CKF_TOKEN ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_PRIVATE, bTrue);
    tplGen.AppendOnce(CKA_MODIFIABLE, ckflags & CKF_MODIFIABLE ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_LABEL, label);
    // Table 24
    tplGen.AppendOnce(CKA_ID, label);
    tplGen.AppendOnce(CKA_DERIVE, ckflags & CKF_DERIVE ? bTrue : bFalse);
    // Table 25
    tplGen.AppendOnce(CKA_ENCRYPT, ckflags & CKF_ENCRYPT ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_VERIFY, ckflags & CKF_VERIFY ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_WRAP, ckflags & CKF_WRAP ? bTrue : bFalse);
    // Table 32
    tplGen.AppendOnce(CKA_SENSITIVE, bTrue);
    tplGen.AppendOnce(CKA_DECRYPT, ckflags & CKF_DECRYPT ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_SIGN, ckflags & CKF_SIGN ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_UNWRAP, ckflags & CKF_UNWRAP ? bTrue : bFalse);
    tplGen.AppendOnce(CKA_EXTRACTABLE, ckflags & CKF_EXTRACTABLE ? bTrue : bFalse);
    // keyType-specific
    if (spec.keyType == CKK_AES) {
        tplGen.AppendOnce(CKA_KEY_TYPE, spec.keyType);
        tplGen.AppendOnce(CKA_VALUE_LEN, (spec.keySizeBits / 8));
    } else if (spec.keyType == CKK_DES3) {
        tplGen.AppendOnce(CKA_KEY_TYPE, spec.keyType);
        // CKA_VALUE_LEN is invalid attribute type wrt CKK_DES3
    }
}

void HsmSecretKey::ReportStatus(const char *pre, CK_RV rv) const {
    if (rv == CKR_OK) {
        HSM_INFO(("%s: keyType = %s (0x%X), keySizeBits = %u, hSecret = %u", pre,
                 HsmUtil::StringFromKeyType(keyType), (unsigned)keyType,
                 (unsigned)keySizeBits, (unsigned)hSecretObject));
    } else {
        HSM_ERROR(("%s: rv = 0x%X", pre, (unsigned)rv));
    }
}

CK_RV HsmSecretKey::EncryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const {
    return _EncryptDecryptBlob(hSession, in, out, false);
}

CK_RV HsmSecretKey::DecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const {
    return _EncryptDecryptBlob(hSession, in, out, true);
}

CK_RV HsmSecretKey::_EncryptDecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out, bool fDecrypt) const {
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_MECHANISM mech = { 0, 0, 0 };
    CK_BYTE_PTR pOut = 0;
    CK_ULONG ulOutLen = 0;

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);

    // initialize mech
    memset(&mech, 0, sizeof(mech));
    if (keyType == CKK_AES) {
        if (HsmConfig::WantCipher("CKM_AES_KEY_WRAP_KWP")) {
            mech.mechanism = CKM_AES_KEY_WRAP_KWP;
            rv = CKR_OK;
        } else if (HsmConfig::WantCipher("CKM_AES_KWP")) {
            mech.mechanism = CKM_AES_KWP;
            rv = CKR_OK;
        } else {
            rv = CKR_MECHANISM_INVALID;
        }
    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_Encrypt/C_Decrypt
    if (fDecrypt) {
        if (rv == CKR_OK) {
            rv = P11->C_DecryptInit(hSession, &mech, GetSecretKeyHandle());
        }

        if (rv == CKR_OK) {
            rv = P11->C_Decrypt(hSession, in->c_value(), in->c_valueLen(), NULL, &ulOutLen);
        }

    } else {
        if (rv == CKR_OK) {
            rv = P11->C_EncryptInit(hSession, &mech, GetSecretKeyHandle());
        }

        if (rv == CKR_OK) {
            rv = P11->C_Encrypt(hSession, in->c_value(), in->c_valueLen(), NULL, &ulOutLen);
        }
    }

    if (rv == CKR_OK) {
        HSM_ASSERT(ulOutLen);
        pOut = new CK_BYTE[ulOutLen];
        HSM_ASSERT(pOut);
    }

    if (fDecrypt) {
        if (rv == CKR_OK) {
            rv = P11->C_Decrypt(hSession, in->c_value(), in->c_valueLen(), pOut, &ulOutLen);
        }
    } else {
        if (rv == CKR_OK) {
            rv = P11->C_Encrypt(hSession, in->c_value(), in->c_valueLen(), pOut, &ulOutLen);
        }
    }

    if (rv == CKR_OK) {
        (*out) = new HsmBlob(pOut, ulOutLen);
    }

    delete pOut;

    return rv;
}
