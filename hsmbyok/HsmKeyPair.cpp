/*****************************************************************************
*
* Copyright (c) 2019-2020 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#include "HsmKeyPair.h"
#include "HsmSecretKey.h"
#include "HsmConfig.h"
#include "HsmUtils.h"

//
// standard curves (P-256, P-384, P-521, P-256K)
//

#define MAX_CURVE_BYTES 10

typedef struct curve_s {
    CK_BYTE params[MAX_CURVE_BYTES];
    CK_ULONG paramsLen;
    CK_ULONG keySizeBits;
    const char *name;
    const char *altName;
} curve_t;

static curve_t curves[] = {
    // standard
    { { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }, 10, 256, "X9_62_prime256v1", "P-256" },
    { { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 }, 7, 384, "secp384r1", "P-384" },
    { { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 }, 7, 521, "secp521r1", "P-521" },
    // by request
    { { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A }, 7, 256, "secp256k1", "P-256K" },
};

//
// HsmKeyPair
//

HsmKeyPair::HsmKeyPair() : hPrivateObject(CK_INVALID_OBJECT_HANDLE), hPublicObject(CK_INVALID_OBJECT_HANDLE) {
    memset(&kek, 0, sizeof(kek));
}

HsmKeyPair::~HsmKeyPair() {}

// zeroize handles but not the public key cache (kek)
void HsmKeyPair::ZeroizeHandles() {
    HsmKey::ZeroizeHandles();
    hPrivateObject = CK_INVALID_OBJECT_HANDLE;
    hPublicObject = CK_INVALID_OBJECT_HANDLE;
}

// import the public key (the private key will remain NULL)
// usually a session key used for verifying and/or wrapping
CK_RV HsmKeyPair::ImportPublicKey(CK_SESSION_HANDLE hSession, const HsmPublicKeyBlob *kekblob) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_OBJECT_CLASS ckoPublic = CKO_PUBLIC_KEY;
    CK_BBOOL bTrue = CK_TRUE;

    CK_ATTRIBUTE _tplPublic[] = {
        { CKA_CLASS, &ckoPublic, sizeof(ckoPublic) },
        { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
        { CKA_KEY_TYPE, 0, 0 },
#if defined(LUNA_NO_SESSION_OBJECTS)
        // FIXME: DSSM cannot handle session objects!?
        { CKA_TOKEN, &bTrue, sizeof(bTrue) },
#endif
    };

    HsmTemplate tplPublic(_tplPublic, DIM(_tplPublic));

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hPublicObject == CK_INVALID_OBJECT_HANDLE);
    HSM_ASSERT(hPrivateObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;

    // initialize template
    {
        kek_t tmp;
        memcpy(&tmp, kekblob->c_value(), MIN(kekblob->c_valueLen(), sizeof(tmp)));
        if (tmp.magic == CKA_RSA_PUBLIC_BLOB) {
            keyType = CKK_RSA;
            HSM_ASSERT((tmp.u.rsa.modLen % 8) == 0);
            HSM_ASSERT(tmp.u.rsa.modLen <= sizeof(tmp.u.rsa.mod));
            HSM_ASSERT(tmp.u.rsa.expLen <= sizeof(tmp.u.rsa.exp));
            keySizeBits = (tmp.u.rsa.modLen * 8);
            tplPublic.SetOnce(CKA_KEY_TYPE, keyType);
            tplPublic.AppendOnce(CKA_WRAP, bTrue);
            tplPublic.AppendOnce(CKA_MODULUS, tmp.u.rsa.mod, tmp.u.rsa.modLen);
            tplPublic.AppendOnce(CKA_PUBLIC_EXPONENT, tmp.u.rsa.exp, tmp.u.rsa.expLen);
            rv = CKR_OK;

        } else if (tmp.magic == CKA_EC_PUBLIC_BLOB) {
            keyType = CKK_EC;
            HSM_ASSERT(tmp.u.ec.pointLen <= sizeof(tmp.u.ec.point));
            HSM_ASSERT(tmp.u.ec.paramsLen <= sizeof(tmp.u.ec.params));
            for (size_t i = 0; i < DIM(curves); i++) {
                if ((curves[i].paramsLen == tmp.u.ec.paramsLen) &&
                    (memcmp(curves[i].params, tmp.u.ec.params, curves[i].paramsLen) == 0)) {
                    keySizeBits = curves[i].keySizeBits;
                    rv = CKR_OK;
                }
            }
            tplPublic.SetOnce(CKA_KEY_TYPE, keyType);
            tplPublic.AppendOnce(CKA_EC_POINT, tmp.u.ec.point, tmp.u.ec.pointLen);
            tplPublic.AppendOnce(CKA_EC_PARAMS, tmp.u.ec.params, tmp.u.ec.paramsLen);

        } else {
            // unknown keyType
            HSM_ERROR(("unknown keyType magic number: 0x%08X", (unsigned)tmp.magic));
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // C_CreateObject
    if (rv == CKR_OK) {
        rv = P11->C_CreateObject(hSession, tplPublic.c_array(), tplPublic.c_count(), &hPublicObject);
    }

    //ReportStatus("ImportPublicKey", rv);
    ReportStatus(__HSM_FUNC__, rv);
    return rv;
}

// export public key from the public key cache (kek)
CK_RV HsmKeyPair::ExportPublicKey(CK_SESSION_HANDLE hSession, HsmPublicKeyBlob **ppblob) {
    HSM_ASSERT(hSharedSession != CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType != CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits != CK_INVALID_KEY_SIZE_BITS);
    // HSM_ASSERT(hPublicObject != CK_INVALID_OBJECT_HANDLE);
    // HSM_ASSERT(hPrivateObject != CK_INVALID_OBJECT_HANDLE);
    HSM_ASSERT(kek.magic == CKA_RSA_PUBLIC_BLOB || kek.magic == CKA_EC_PUBLIC_BLOB);
    HsmPublicKeyBlob *pblob = new HsmPublicKeyBlob((void *)&kek, sizeof(kek));
    HSM_ASSERT(pblob);
    *ppblob = pblob;
    return pblob == NULL ? CKR_GENERAL_ERROR : CKR_OK;
}

// load private key details by object handle (usually a generated or unwrapped key handle)
// also load the related public key details
// (optional) if public key not found then create the public key as a session object
// (C_CreateObject)
CK_RV HsmKeyPair::LoadKeyPair(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_OBJECT_HANDLE hPublic,
                              bool flagCreatePublic) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_ULONG tmpKeyType = CK_INVALID_KEY_TYPE;
    CK_BYTE ckaLabel[CK_MAX_LABEL_BYTES] = { 0 };
    CK_BYTE ckaExponent[CK_MAX_PUBLIC_EXPONENT_BYTES] = { 0 };
    CK_BYTE ckaModulus[CK_MAX_MODULUS_BYTES] = { 0 };
    CK_BYTE ckaEcParams[CK_MAX_EC_PARAMS_BYTES] = { 0 };
    CK_BYTE ckaEcPoint[CK_MAX_EC_POINT_BYTES] = { 0 };

    // template to read keyType
    CK_ATTRIBUTE _tplReadType[] = { { CKA_KEY_TYPE, &tmpKeyType, sizeof(tmpKeyType) },
                                    { CKA_LABEL, &ckaLabel, sizeof(ckaLabel) } };

    // template to read RSA key attributes
    CK_ATTRIBUTE _tplReadRsa[] = { { CKA_PUBLIC_EXPONENT, &ckaExponent, sizeof(ckaExponent) },
                                   { CKA_MODULUS, &ckaModulus, sizeof(ckaModulus) } };

    // template to read EC key attributes
    CK_ATTRIBUTE _tplReadEc[] = { { CKA_EC_PARAMS, &ckaEcParams, sizeof(ckaEcParams) },
                                  { CKA_EC_POINT, &ckaEcPoint, sizeof(ckaEcPoint) } };

    CK_OBJECT_CLASS ckoPublic = CKO_PUBLIC_KEY;
    CK_BBOOL bTrue = CK_TRUE;

    // template to find the public key
    CK_ATTRIBUTE _tplPublicFind[] = { { CKA_CLASS, &ckoPublic, sizeof(ckoPublic) },
                                      { CKA_TOKEN, &bTrue, sizeof(bTrue) },
                                      { CKA_PRIVATE, &bTrue, sizeof(bTrue) },
                                      { CKA_LABEL, 0, 0 },
                                      { CKA_KEY_TYPE, 0, 0 } };

    HsmTemplate tplPublicFind(_tplPublicFind, DIM(_tplPublicFind));

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hPublicObject == CK_INVALID_OBJECT_HANDLE);
    HSM_ASSERT(hPrivateObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;
    hPrivateObject = hObject;
    hPublicObject = hPublic;

    // C_GetAttributeValue
    rv = P11->C_GetAttributeValue(hSession, hPrivateObject, _tplReadType, DIM(_tplReadType));
    if (!HsmUtil::IsKeyPairType(tmpKeyType)) { // keyType
        rv = CKR_KEY_TYPE_INCONSISTENT;
    } else if (_tplReadType[1].ulValueLen < 1) { // label
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (rv == CKR_OK) {
        if (tmpKeyType == CKK_RSA) {
            rv = P11->C_GetAttributeValue(hSession, hPrivateObject, _tplReadRsa, DIM(_tplReadRsa));
        } else if (tmpKeyType == CKK_EC) {
            rv = P11->C_GetAttributeValue(hSession, hPrivateObject, _tplReadEc, DIM(_tplReadEc));
        } else {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // post-initialize
    if (rv == CKR_OK) {
        tplPublicFind.SetOnce(CKA_KEY_TYPE, tmpKeyType); // keyType
        tplPublicFind.SetOnce(CKA_LABEL, _tplReadType[1].pValue, _tplReadType[1].ulValueLen); // label
        if (tmpKeyType == CKK_RSA) {
            kek.magic = CKA_RSA_PUBLIC_BLOB;
            kek.u.rsa.expLen = _tplReadRsa[0].ulValueLen; // exponent
            memcpy(kek.u.rsa.exp, _tplReadRsa[0].pValue, _tplReadRsa[0].ulValueLen); // exponent
            kek.u.rsa.modLen = _tplReadRsa[1].ulValueLen; // modulus
            memcpy(kek.u.rsa.mod, _tplReadRsa[1].pValue, _tplReadRsa[1].ulValueLen); // modulus

            keyType = CKK_RSA;
            keySizeBits = (kek.u.rsa.modLen * 8);

            tplPublicFind.AppendOnce(CKA_PUBLIC_EXPONENT, kek.u.rsa.exp, kek.u.rsa.expLen);
            tplPublicFind.AppendOnce(CKA_MODULUS, kek.u.rsa.mod, kek.u.rsa.modLen);

        } else if (tmpKeyType == CKK_EC) {
            kek.magic = CKA_EC_PUBLIC_BLOB;
            kek.u.ec.paramsLen = _tplReadEc[0].ulValueLen; // ecParams
            memcpy(kek.u.ec.params, _tplReadEc[0].pValue, _tplReadEc[0].ulValueLen); // ecParams
            kek.u.ec.pointLen = _tplReadEc[1].ulValueLen; // ecPoint
            memcpy(kek.u.ec.point, _tplReadEc[1].pValue, _tplReadEc[1].ulValueLen); // ecPoint

            keyType = CKK_EC;
            for (size_t i = 0; i < DIM(curves); i++) {
                if ((curves[i].paramsLen == kek.u.ec.paramsLen) &&
                    (memcmp(curves[i].params, kek.u.ec.params, curves[i].paramsLen) == 0)) {
                    keySizeBits = curves[i].keySizeBits;
                }
            }

            tplPublicFind.AppendOnce(CKA_EC_PARAMS, kek.u.ec.params, kek.u.ec.paramsLen);
            tplPublicFind.AppendOnce(CKA_EC_POINT, kek.u.ec.point, kek.u.ec.pointLen);

        } else {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // LoadPublicKey
    if ((rv == CKR_OK) && (hPublicObject == CK_INVALID_OBJECT_HANDLE)) {

        // find or create the corresponding public key
        if (rv == CKR_OK) {
            rv = P11->C_FindObjectsInit(hSession, tplPublicFind.c_array(), tplPublicFind.c_count());
        }

        if (rv == CKR_OK) {
            CK_OBJECT_HANDLE hFoundObjects[2] = { 0, 0 };
            CK_ULONG ulObjectCount = 0;
            HSM_ASSERT(DIM(hFoundObjects) >= 2);
            CK_RV rvfind = P11->C_FindObjects(hSession, hFoundObjects, DIM(hFoundObjects), &ulObjectCount);
            // the count can equal one or more; i.e., multiple public keys can share the same
            // modulus
            if (rvfind == CKR_OK) {
                if (ulObjectCount == 0) {
                    rv = CKR_OBJECT_NOT_FOUND;
                } else {
                    hPublicObject = hFoundObjects[0];
                    rv = CKR_OK;
                }
            } else {
                rv = rvfind;
            }
            (void)P11->C_FindObjectsFinal(hSession);
        }

        // C_CreateObject
        if (rv == CKR_OBJECT_NOT_FOUND) {
            if (flagCreatePublic) {
                HsmPublicKeyBlob *tmpBlob = 0;
                rv = ExportPublicKey(hSession, &tmpBlob);
                if (rv == CKR_OK) {
                    const CK_OBJECT_HANDLE tmp_priv = hPrivateObject;
                    ZeroizeHandles(); // for ImportPublicKey that checks re-initialization
                    rv = ImportPublicKey(hSession, tmpBlob);
                    hPrivateObject = tmp_priv;
                }
                delete tmpBlob;
            } else {
                rv = CKR_OK;
            }
        }
    }

    //ReportStatus("LoadKeyPair", rv);
    ReportStatus(__HSM_FUNC__, rv);
    return rv;
}

// find private key by label and load private and public key details
CK_RV HsmKeyPair::FindKeyPair(CK_SESSION_HANDLE hSession, std::string label) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    const CK_OBJECT_CLASS ckoPrivate = CKO_PRIVATE_KEY;
    const CK_BBOOL bTrue = CK_TRUE;

    // template to find the private key
    CK_ATTRIBUTE _tplFind[] = { { CKA_CLASS, 0, 0 }, { CKA_TOKEN, 0, 0 }, { CKA_PRIVATE, 0, 0 }, { CKA_LABEL, 0, 0 } };

    HsmTemplate tplFind(_tplFind, DIM(_tplFind));

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hPublicObject == CK_INVALID_OBJECT_HANDLE);
    HSM_ASSERT(hPrivateObject == CK_INVALID_OBJECT_HANDLE);

    // initialize members
    hSharedSession = hSession;

    // initialize template
    tplFind.SetOnce(CKA_CLASS, ckoPrivate);
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
        // the count must equal one; i.e., multiple private keys cannot share the same label
        if (rvfind == CKR_OK) {
            if (ulObjectCount == 0) {
                rv = CKR_OBJECT_NOT_FOUND;
            } else if (ulObjectCount == 1) {
                hPrivateObject = hFoundObjects[0];
                rv = CKR_OK;
            } else {
                rv = CKR_MULTIPLE_OBJECTS;
            }
        } else {
            rv = rvfind;
        }
        (void)P11->C_FindObjectsFinal(hSession);
    }

    // LoadKeyPair
    if (rv == CKR_OK) {
        const CK_OBJECT_HANDLE tmp_priv = hPrivateObject;
        ZeroizeHandles(); // for LoadKeyPair that checks re-initialization
        rv = LoadKeyPair(hSession, tmp_priv);
    }

    return rv;
}

// generate a new keypair (asymmetric)
CK_RV HsmKeyPair::GenerateKeyPair(CK_SESSION_HANDLE hSession, const CK_KEY_SPEC &spec, std::string label,
                                  CK_FLAGS ckflags) {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechGen = { 0, 0, 0 };

    HsmTemplate tplPublic;
    HsmTemplate tplPrivate;

    // check members (prevent multiple initializations)
    HSM_ASSERT(hSharedSession == CK_INVALID_SESSION_HANDLE);
    HSM_ASSERT(keyType == CK_INVALID_KEY_TYPE);
    HSM_ASSERT(keySizeBits == CK_INVALID_KEY_SIZE_BITS);
    HSM_ASSERT(hPublicObject == CK_INVALID_OBJECT_HANDLE);
    HSM_ASSERT(hPrivateObject == CK_INVALID_OBJECT_HANDLE);

    // init members
    hSharedSession = hSession;
    keyType = spec.keyType;
    keySizeBits = spec.keySizeBits;
    if (keyType == CKK_RSA) {
        mechGen.mechanism = CKM_RSA_X9_31_KEY_PAIR_GEN;
        rv = CKR_OK;
    } else if (keyType == CKK_EC) {
        mechGen.mechanism = CKM_EC_KEY_PAIR_GEN;
        rv = CKR_OK;
    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_GenerateKeyPair
    if (rv == CKR_OK) {
        SetPublicKeyTemplate(tplPublic, spec, label, ckflags);
        SetPrivateKeyTemplate(tplPrivate, spec, label, ckflags);
        rv = P11->C_GenerateKeyPair(hSession, &mechGen, tplPublic.c_array(), tplPublic.c_count(), tplPrivate.c_array(),
                                    tplPrivate.c_count(), &hPublicObject, &hPrivateObject);
    }

    // LoadKeyPair
    if (rv == CKR_OK) {
        const CK_OBJECT_HANDLE tmp_pub = hPublicObject;
        const CK_OBJECT_HANDLE tmp_priv = hPrivateObject;
        ZeroizeHandles(); // for LoadKeyPair that checks re-initialization
        rv = LoadKeyPair(hSession, tmp_priv, tmp_pub);
        if (rv != CKR_OK) {
            // destroy generated keypair on error
            (void)P11->C_DestroyObject(hSession, tmp_pub);
            (void)P11->C_DestroyObject(hSession, tmp_priv);
            hPublicObject = CK_INVALID_OBJECT_HANDLE;
            hPrivateObject = CK_INVALID_OBJECT_HANDLE;
        }
    }

    //ReportStatus("GenerateKeyPair", rv);
    ReportStatus(__HSM_FUNC__, rv);
    return rv;
}

// wrap a secret key with this public key
CK_RV HsmKeyPair::WrapSecretKey(CK_SESSION_HANDLE hSession, const HsmSecretKey *sk, HsmWrappedKeyBlob **ppblob) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechWrap = { 0, 0, 0 };
    CK_BYTE_PTR pWrappedKey = 0;
    CK_ULONG ulWrappedKeyLen = 0;
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = { 0 };

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);
    HSM_ASSERT(hSession == sk->GetSharedSessionHandle());

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_RSA) {
        mechWrap.mechanism = CKM_RSA_PKCS_OAEP;
        mechWrap.pParameter = &oaepParams;
        mechWrap.ulParameterLen = sizeof(oaepParams);

        memset(&oaepParams, 0, sizeof(oaepParams));
        oaepParams.source = CKZ_DATA_SPECIFIED;
        rv = _SetOaepHashType(oaepParams);

    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_WrapKey
    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, GetWrappingKeyHandle(), sk->GetSecretKeyHandle(), NULL,
                            &ulWrappedKeyLen);
    }

    if (rv == CKR_OK) {
        HSM_ASSERT(ulWrappedKeyLen);
        pWrappedKey = new CK_BYTE[ulWrappedKeyLen];
        HSM_ASSERT(pWrappedKey);
    }

    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, GetWrappingKeyHandle(), sk->GetSecretKeyHandle(), pWrappedKey,
                            &ulWrappedKeyLen);
    }

    // report success or failure
    if (rv == CKR_OK) {
        (*ppblob) = new HsmWrappedKeyBlob(pWrappedKey, ulWrappedKeyLen);
    }

    delete pWrappedKey;

    return rv;
}

// wrap a key using this private key (CKM_RSA_AES_KEY_WRAP where available)
CK_RV HsmKeyPair::WrapKeyMethod1(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const {
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_MECHANISM mechWrap = { 0, 0, 0 };
    CK_BYTE_PTR pWrappedKey = 0;
    CK_ULONG ulWrappedKeyLen = 0;
    CK_RSA_AES_KEY_WRAP_PARAMS rsa_aes_key_wrap = { 0 };
    CK_RSA_PKCS_OAEP_PARAMS rsa_pkcs_oaep = { 0 };

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);
    HSM_ASSERT(hSession == key->GetSharedSessionHandle());

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_RSA) {
        mechWrap.mechanism = CKM_RSA_AES_KEY_WRAP;
        mechWrap.pParameter = &rsa_aes_key_wrap;
        mechWrap.ulParameterLen = sizeof(rsa_aes_key_wrap);

        memset(&rsa_aes_key_wrap, 0, sizeof(rsa_aes_key_wrap));
        rsa_aes_key_wrap.ulAESKeyBits = 256;
        rsa_aes_key_wrap.pOAEPParams = &rsa_pkcs_oaep;

        memset(&rsa_pkcs_oaep, 0, sizeof(rsa_pkcs_oaep));
        rsa_pkcs_oaep.source = CKZ_DATA_SPECIFIED;
        rv = _SetOaepHashType(rsa_pkcs_oaep);

    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_WrapKey
    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, GetWrappingKeyHandle(), key->GetKeyHandle(), NULL, &ulWrappedKeyLen);
    }

    if (rv == CKR_OK) {
        HSM_ASSERT(ulWrappedKeyLen);
        pWrappedKey = new CK_BYTE[ulWrappedKeyLen];
        HSM_ASSERT(pWrappedKey);
    }

    if (rv == CKR_OK) {
        rv = P11->C_WrapKey(hSession, &mechWrap, GetWrappingKeyHandle(), key->GetKeyHandle(), pWrappedKey,
                            &ulWrappedKeyLen);
    }

    // report success or failure
    if (rv == CKR_OK) {
        (*ppblob) = new HsmWrappedKeyBlob(pWrappedKey, ulWrappedKeyLen);
    }

    delete pWrappedKey;

    return rv;
}

// concatenate two discrete wrapping operations
CK_RV HsmKeyPair::WrapKeyMethod2(CK_SESSION_HANDLE hSession, const HsmKey *key, HsmWrappedKeyBlob **ppblob) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    const CK_KEY_SPEC aesKeySpec = { CKK_AES, 256, 0 };
    HsmSecretKey *sk = new HsmSecretKey();
    HsmWrappedKeyBlob *pblob1 = 0;
    HsmWrappedKeyBlob *pblob2 = 0;
    std::string tmpLabel("temp-wrapping-key");

#if defined(LUNA_NO_SESSION_OBJECTS)
    // FIXME: DSSM cannot handle session objects!?
    rv = sk->GenerateSecretKey(hSession, aesKeySpec, tmpLabel, (CKF_EXTRACTABLE | CKF_WRAP | CKF_TOKEN));
#else
    rv = sk->GenerateSecretKey(hSession, aesKeySpec, tmpLabel, (CKF_EXTRACTABLE | CKF_WRAP));
#endif
    if (rv == CKR_OK) {
        rv = this->WrapSecretKey(hSession, sk, &pblob1);
    }

    if (rv == CKR_OK) {
        rv = sk->WrapKey(hSession, key, &pblob2);
    }

    if (rv == CKR_OK) {
        pblob1->Concatenate(*pblob2);
        *ppblob = pblob1; // take ownership of pblob1
        pblob1 = 0;
    }

    delete pblob1;
    delete pblob2;

    return rv;
}

// unwrap a secret key with this private key
CK_RV HsmKeyPair::UnwrapSecretKey(CK_SESSION_HANDLE hSession, HsmSecretKey **ppsk, const HsmWrappedKeyBlob *pblob,
                                  const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechWrap = { 0, 0, 0 };
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = { 0 };

    HsmTemplate tplSecret;
    CK_OBJECT_HANDLE hObject = CK_INVALID_OBJECT_HANDLE;
    HsmSecretKey *sk = new HsmSecretKey();

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_RSA) {
        mechWrap.mechanism = CKM_RSA_PKCS_OAEP;
        mechWrap.pParameter = &oaepParams;
        mechWrap.ulParameterLen = sizeof(oaepParams);

        memset(&oaepParams, 0, sizeof(oaepParams));
        oaepParams.source = CKZ_DATA_SPECIFIED;
        rv = _SetOaepHashType(oaepParams);

    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    if (rv == CKR_OK) {
        if (!HsmUtil::IsSecretKeyType(spec.keyType)) {
            rv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    if (rv == CKR_OK) {
#if defined(LUNA_NO_SESSION_OBJECTS)
        // FIXME: DSSM cannot handle session objects!?
        HsmSecretKey::SetSecretKeyTemplate(tplSecret, spec, label, ckflags | CKF_TOKEN);
#else
        HsmSecretKey::SetSecretKeyTemplate(tplSecret, spec, label, ckflags);
#endif
        rv = P11->C_UnwrapKey(hSession, &mechWrap, GetUnwrappingKeyHandle(), pblob->c_value(), pblob->c_valueLen(),
                              tplSecret.c_array(), tplSecret.c_count(), &hObject);
    }

    if (rv == CKR_OK) {
        rv = sk->LoadSecretKey(hSession, hObject);
        if (rv != CKR_OK) {
            // destroy unwrapped key on error
            (void)P11->C_DestroyObject(hSession, hObject);
            hObject = CK_INVALID_OBJECT_HANDLE;
        }
    }

    // report success or failure
    if (rv == CKR_OK) {
        (*ppsk) = sk; // take ownership of sk
        sk = 0;
    }

    delete sk;

    return rv;
}

// unwrap a private key using this private key (CKM_RSA_AES_KEY_WRAP where available)
CK_RV HsmKeyPair::UnwrapKeyMethod1(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob,
                                   const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_MECHANISM mechWrap = { 0, 0, 0 };
    CK_RSA_AES_KEY_WRAP_PARAMS rsa_aes_key_wrap = { 0 };
    CK_RSA_PKCS_OAEP_PARAMS rsa_pkcs_oaep = { 0 };
    HsmTemplate *pTemplate = new HsmTemplate;
    CK_OBJECT_HANDLE hObject = CK_INVALID_OBJECT_HANDLE;
    HsmKey *key = 0;

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);

    // initialize mech
    memset(&mechWrap, 0, sizeof(mechWrap));
    if (keyType == CKK_RSA) {
        mechWrap.mechanism = CKM_RSA_AES_KEY_WRAP;
        mechWrap.pParameter = &rsa_aes_key_wrap;
        mechWrap.ulParameterLen = sizeof(rsa_aes_key_wrap);

        memset(&rsa_aes_key_wrap, 0, sizeof(rsa_aes_key_wrap));
        rsa_aes_key_wrap.ulAESKeyBits = 256;
        rsa_aes_key_wrap.pOAEPParams = &rsa_pkcs_oaep;

        memset(&rsa_pkcs_oaep, 0, sizeof(rsa_pkcs_oaep));
        rsa_pkcs_oaep.source = CKZ_DATA_SPECIFIED;
        rv = _SetOaepHashType(rsa_pkcs_oaep);

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
        rv = P11->C_UnwrapKey(hSession, &mechWrap, GetUnwrappingKeyHandle(), pblob->c_value(), pblob->c_valueLen(),
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

    // report success or failure
    if (rv == CKR_OK) {
        (*ppkey) = key; // take ownership of key
        key = 0;
    }

    delete key;
    delete pTemplate;

    return rv;
}

// unwrap two blobs (CKM_RSA_PKCS_OAEP and CKM_AES_KEY_WRAP_PAD)
CK_RV HsmKeyPair::UnwrapKeyMethod2(CK_SESSION_HANDLE hSession, HsmKey **ppkey, const HsmWrappedKeyBlob *pblob,
                                   const CK_KEY_SPEC &spec, std::string label, CK_FLAGS ckflags) const {
    CK_RV rv = CKR_FUNCTION_FAILED;

    const CK_KEY_SPEC aesKeySpec = { CKK_AES, 256, 0 };
    HsmWrappedKeyBlob *pblob1 = 0, *pblob2 = 0;
    CK_ULONG len1 = 0, len2 = 0;
    HsmSecretKey *sk = 0;
    HsmKey *key = 0;

    HSM_ASSERT(keySizeBits != CK_INVALID_KEY_SIZE_BITS);
    len1 = keySizeBits / 8;
    HSM_ASSERT(pblob->c_valueLen() > len1);
    len2 = pblob->c_valueLen() - len1;
    pblob1 = new HsmWrappedKeyBlob(pblob->c_value(), len1);
    pblob2 = new HsmWrappedKeyBlob((pblob->c_value() + len1), len2);

    rv = this->UnwrapSecretKey(hSession, &sk, pblob1, aesKeySpec, "temp-secret-unwrapping-key", CKF_UNWRAP);
    if (rv == CKR_OK) {
        rv = sk->UnwrapKey(hSession, &key, pblob2, spec, label, ckflags);
    }

    if (rv == CKR_OK) {
        (*ppkey) = key; // take ownership of key
        key = 0;
    }

    delete pblob1;
    delete pblob2;
    delete sk;
    delete key;

    return rv;
}

// set attribute template for generated or imported public key
void HsmKeyPair::SetPublicKeyTemplate(HsmTemplate &tplPublic, const CK_KEY_SPEC &spec, const std::string &label,
                                      CK_FLAGS ckflags) {
    const CK_OBJECT_CLASS ckoPublic = CKO_PUBLIC_KEY;
    const CK_BBOOL bTrue = CK_TRUE;
    const CK_BBOOL bFalse = CK_FALSE;
    // Table 14
    tplPublic.AppendOnce(CKA_CLASS, ckoPublic);
    // Table 18
    tplPublic.AppendOnce(CKA_TOKEN, ckflags & CKF_TOKEN ? bTrue : bFalse);
    tplPublic.AppendOnce(CKA_PRIVATE, bTrue);
    tplPublic.AppendOnce(CKA_MODIFIABLE, ckflags & CKF_MODIFIABLE ? bTrue : bFalse);
    tplPublic.AppendOnce(CKA_LABEL, label);
    // Table 24
    tplPublic.AppendOnce(CKA_ID, label);
    tplPublic.AppendOnce(CKA_DERIVE, ckflags & CKF_DERIVE ? bTrue : bFalse);
    // Table 25
    tplPublic.AppendOnce(CKA_ENCRYPT, ckflags & CKF_ENCRYPT ? bTrue : bFalse);
    tplPublic.AppendOnce(CKA_VERIFY, ckflags & CKF_VERIFY ? bTrue : bFalse);
    // keyType-specific
    if (spec.keyType == CKK_RSA) {
        CK_BYTE exp[3] = { 0x01, 0x00, 0x01 }; // FIXME: configurable public exponent!
        CK_ULONG expLen = sizeof(exp);
        tplPublic.AppendOnce(CKA_KEY_TYPE, spec.keyType);
        tplPublic.AppendOnce(CKA_VERIFY_RECOVER, ckflags & CKF_VERIFY_RECOVER ? bTrue : bFalse);
        tplPublic.AppendOnce(CKA_WRAP, ckflags & CKF_WRAP ? bTrue : bFalse);
        tplPublic.AppendOnce(CKA_MODULUS_BITS, spec.keySizeBits);
        tplPublic.AppendOnce(CKA_PUBLIC_EXPONENT, exp, expLen);
    } else if (spec.keyType == CKK_EC) {
        tplPublic.AppendOnce(CKA_KEY_TYPE, spec.keyType);
        for (size_t i = 0; i < DIM(curves); i++) {
            if (spec.curveName) {
                if ((spec.keySizeBits == curves[i].keySizeBits) &&
                    (!HsmSys::strcasecmp(spec.curveName, curves[i].name) || !HsmSys::strcasecmp(spec.curveName, curves[i].altName))) {
                    tplPublic.AppendOnce(CKA_EC_PARAMS, curves[i].params, curves[i].paramsLen);
                }
            } else {
                HSM_ERROR(("curveName not specified"));
            }
        }
    }
}

// set attribute template for generated or unwrapped private key
void HsmKeyPair::SetPrivateKeyTemplate(HsmTemplate &tplPrivate, const CK_KEY_SPEC &spec, const std::string &label,
                                       CK_FLAGS ckflags) {
    const CK_OBJECT_CLASS ckoPrivate = CKO_PRIVATE_KEY;
    const CK_BBOOL bTrue = CK_TRUE;
    const CK_BBOOL bFalse = CK_FALSE;
    // Table 14
    tplPrivate.AppendOnce(CKA_CLASS, ckoPrivate);
    // Table 18
    tplPrivate.AppendOnce(CKA_TOKEN, ckflags & CKF_TOKEN ? bTrue : bFalse);
    tplPrivate.AppendOnce(CKA_PRIVATE, bTrue);
    tplPrivate.AppendOnce(CKA_MODIFIABLE, ckflags & CKF_MODIFIABLE ? bTrue : bFalse);
    tplPrivate.AppendOnce(CKA_LABEL, label);
    // Table 24
    tplPrivate.AppendOnce(CKA_ID, label);
    tplPrivate.AppendOnce(CKA_DERIVE, ckflags & CKF_DERIVE ? bTrue : bFalse);
    // Table 32
    tplPrivate.AppendOnce(CKA_SENSITIVE, bTrue);
    tplPrivate.AppendOnce(CKA_DECRYPT, ckflags & CKF_DECRYPT ? bTrue : bFalse);
    tplPrivate.AppendOnce(CKA_SIGN, ckflags & CKF_SIGN ? bTrue : bFalse);
    tplPrivate.AppendOnce(CKA_EXTRACTABLE, ckflags & CKF_EXTRACTABLE ? bTrue : bFalse);
    // keyType-specific
    if (spec.keyType == CKK_RSA) {
        tplPrivate.AppendOnce(CKA_KEY_TYPE, spec.keyType);
        tplPrivate.AppendOnce(CKA_SIGN_RECOVER, ckflags & CKF_SIGN_RECOVER ? bTrue : bFalse);
        tplPrivate.AppendOnce(CKA_UNWRAP, ckflags & CKF_UNWRAP ? bTrue : bFalse);
    } else if (spec.keyType == CKK_EC) {
        tplPrivate.AppendOnce(CKA_KEY_TYPE, spec.keyType);
    }
}

#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// import public key from PEM file
CK_RV HsmKeyPair::ImportPublicKey(CK_SESSION_HANDLE hSession, const std::string &pemfile) {
    BIO *in = BIO_new_file(pemfile.c_str(), "r");
    if (in == NULL)
        return CKR_FILE_NOT_FOUND;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(in, NULL, 0, NULL);
    BIO_free(in);
    in = 0;

    if (pkey == NULL)
        return CKR_FILE_IO;

    CK_RV rv = CKR_FUNCTION_FAILED;
    kek_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    if (pkey->type == EVP_PKEY_RSA) {
        tmp.magic = CKA_RSA_PUBLIC_BLOB;
        tmp.u.rsa.expLen = BN_bn2bin(pkey->pkey.rsa->e, tmp.u.rsa.exp);
        HSM_ASSERT(tmp.u.rsa.expLen <= sizeof(tmp.u.rsa.exp));
        HSM_ASSERT(tmp.u.rsa.exp[0] != 0x00);
        tmp.u.rsa.modLen = BN_bn2bin(pkey->pkey.rsa->n, tmp.u.rsa.mod);
        HSM_ASSERT(tmp.u.rsa.modLen <= sizeof(tmp.u.rsa.mod));
        HSM_ASSERT(tmp.u.rsa.mod[0] != 0x00);
        rv = CKR_OK;

    } else if (pkey->type == EVP_PKEY_EC) {
        // FIXME:EC wrapping key is not required yet:tmp.magic = CKA_EC_PUBLIC_BLOB;
        rv = CKR_KEY_TYPE_INCONSISTENT;

    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    if (rv == CKR_OK) {
        HsmPublicKeyBlob *pblob = new HsmPublicKeyBlob((void *)&tmp, sizeof(tmp));
        HSM_ASSERT(pblob);
        rv = ImportPublicKey(hSession, pblob);
        delete pblob;
    }

    EVP_PKEY_free(pkey);

    return rv;
}

CK_RV HsmKeyPair::_SetOaepHashType(CK_RSA_PKCS_OAEP_PARAMS &oaepParams) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    if (HsmConfig::WantCipher("CKG_MGF1_SHA512")) {
        oaepParams.hashAlg = CKM_SHA512;
        oaepParams.mgf = CKG_MGF1_SHA512;
        rv = CKR_OK;
    } else if (HsmConfig::WantCipher("CKG_MGF1_SHA384")) {
        oaepParams.hashAlg = CKM_SHA384;
        oaepParams.mgf = CKG_MGF1_SHA384;
        rv = CKR_OK;
    } else if (HsmConfig::WantCipher("CKG_MGF1_SHA256")) {
        oaepParams.hashAlg = CKM_SHA256;
        oaepParams.mgf = CKG_MGF1_SHA256;
        rv = CKR_OK;
    } else if (HsmConfig::WantCipher("CKG_MGF1_SHA224")) {
        oaepParams.hashAlg = CKM_SHA224;
        oaepParams.mgf = CKG_MGF1_SHA224;
        rv = CKR_OK;
    } else if (HsmConfig::WantCipher("CKG_MGF1_SHA1")) {
        oaepParams.hashAlg = CKM_SHA_1;
        oaepParams.mgf = CKG_MGF1_SHA1;
        rv = CKR_OK;
    } else {
        HSM_ERROR(("missing cipher such as CKG_MGF1_SHA1"));
        rv = CKR_MECHANISM_INVALID;
    }
    return rv;
}

void HsmKeyPair::ReportStatus(const char *pre, CK_RV rv) const {
    if (rv == CKR_OK) {
        HSM_INFO(("%s: keyType = %s (0x%X), keySizeBits = %u, hPublic = %u, hPrivate = %u", pre,
                 HsmUtil::StringFromKeyType(keyType), (unsigned)keyType,
                 (unsigned)keySizeBits, (unsigned)hPublicObject, (unsigned)hPrivateObject));
    } else {
        HSM_ERROR(("%s: rv = 0x%X", pre, (unsigned)rv));
    }
}

CK_RV HsmKeyPair::EncryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const {
    return _EncryptDecryptBlob(hSession, in, out, false);
}

CK_RV HsmKeyPair::DecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out) const {
    return _EncryptDecryptBlob(hSession, in, out, true);
}

CK_RV HsmKeyPair::_EncryptDecryptBlob(CK_SESSION_HANDLE hSession, const HsmBlob *in, HsmBlob **out, bool fDecrypt) const {
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_MECHANISM mech = { 0, 0, 0 };
    CK_BYTE_PTR pOut = 0;
    CK_ULONG ulOutLen = 0;
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = { 0 };

    // assert all keys in the same session
    HSM_ASSERT(hSession == hSharedSession);

    // initialize mech
    memset(&mech, 0, sizeof(mech));
    if (keyType == CKK_RSA) {
        mech.mechanism = CKM_RSA_PKCS_OAEP;
        mech.pParameter = &oaepParams;
        mech.ulParameterLen = sizeof(oaepParams);

        memset(&oaepParams, 0, sizeof(oaepParams));
        oaepParams.source = CKZ_DATA_SPECIFIED;
        rv = _SetOaepHashType(oaepParams);

    } else if (keyType == CKK_EC) {
        // FIXME: ECIES encryption not implemented!
        rv = CKR_KEY_TYPE_INCONSISTENT;

    } else {
        rv = CKR_KEY_TYPE_INCONSISTENT;
    }

    // C_Encrypt/C_Decrypt
    if (fDecrypt) {
        if (rv == CKR_OK) {
            rv = P11->C_DecryptInit(hSession, &mech, GetPrivateKeyHandle());
        }

        if (rv == CKR_OK) {
            rv = P11->C_Decrypt(hSession, in->c_value(), in->c_valueLen(), NULL, &ulOutLen);
        }

    } else {
        if (rv == CKR_OK) {
            rv = P11->C_EncryptInit(hSession, &mech, GetPublicKeyHandle());
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
