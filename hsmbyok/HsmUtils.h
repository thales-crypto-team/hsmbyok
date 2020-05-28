/*****************************************************************************
*
* Copyright (c) 2019 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#ifndef _HSMUTILS_H
#define _HSMUTILS_H

#include "HsmDefs.h"
#include "HsmSys.h"
#include <string>

//
// HsmUtil
//
// misc utility for PKCS#11
//

class HsmUtil {
public:
    static void Print(const char *msg);

    static void PrintLine(const char *pre, const char *msg, CK_RV rv = 0);
    static void PrintError(const char *msg, CK_RV rv = 0) { PrintLine("ERROR", msg, rv); }
    static void PrintWarning(const char *msg, CK_RV rv = 0) { PrintLine("WARNING", msg, rv); }
    static void PrintInfo(const char *msg, CK_RV rv = 0) { PrintLine("INFO", msg, rv); }

    static void PrintLine(const char *pre, const char *msg, const std::string& post);
    static void PrintError(const char *msg, const std::string& post) { PrintLine("ERROR", msg, post); }
    static void PrintWarning(const char *msg, const std::string& post) { PrintLine("WARNING", msg, post); }
    static void PrintInfo(const char *msg, const std::string& post) { PrintLine("INFO", msg, post); }

public:
    static bool IsSecretKeyType(CK_KEY_TYPE type);
    static bool IsKeyPairType(CK_KEY_TYPE type);
    static CK_ULONG GetMaxAttributeSize(CK_ATTRIBUTE_TYPE t);
    static CK_KEY_TYPE KeyTypeFromString(const char *szKeyType);
    static const char* StringFromRV(CK_RV rv);
    static const char* StringFromKeyType(CK_KEY_TYPE ckk);
};

//
// HsmApi
//
// quick access to PKCS#11 library
//

class HsmApi { // namespace
public:
    static CK_RV Init(const char *libraryName, const char *tokenLabel);
    static void Fini();

    static CK_RV LoginCO(const char *coPin);
    static void Logout();

    static CK_SESSION_HANDLE OpenSession();
    static void CloseSession(CK_SESSION_HANDLE hSession);

    static std::string GetTokenInfo() { return szTokenInfo; }

public:
    static CK_FUNCTION_LIST_PTR FunctionList;

private:
    static CK_RV FindSlotIdByLabel(const char *tokenLabel);

private:
    static HsmSys::HLIBRARY handle;
    static CK_SLOT_ID slotId;
    static CK_SESSION_HANDLE hLoginSession;
    static std::string szTokenInfo;
};

#define P11 HsmApi::FunctionList // Shortform. For example use P11->C_SignInit(), etc.

//
// HsmBlob
//
// array of CK_BYTE's
//

class HsmWrappedKeyBlob;
class HsmPublicKeyBlob;

class HsmBlob {
public:
    HsmBlob(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR in, CK_ULONG inlen);
    HsmBlob(const CK_VOID_PTR in, CK_ULONG inlen);
    HsmBlob(CK_ULONG inlen);
    HsmBlob(const std::string &str);
    virtual ~HsmBlob();

    // unsafe copy constructor, assignment operator
    HsmBlob(HsmBlob &) { HSM_BUG(""); }
    HsmBlob &operator=(HsmBlob &) { HSM_BUG(""); }

public:
    CK_ATTRIBUTE_TYPE c_type() const { return type; }
    CK_BYTE_PTR c_value() const { return pValue; }
    CK_ULONG c_valueLen() const { return ulValueLen; }

public:
    void Concatenate(const HsmBlob &src);
    int Compare(const HsmBlob &src) const;

public:
    static CK_VOID_PTR Duplicate(const CK_VOID_PTR in, CK_ULONG inlen);
    static CK_RV WriteBinaryFile(const std::string &filename, const HsmBlob *pblob);
    static CK_ULONG GetFileSize(const std::string &filename);
    static CK_RV ReadBinaryFile(const std::string &filename, HsmBlob **ppBlob);
    static CK_RV ReadBinaryFile(const std::string &filename, HsmWrappedKeyBlob **ppBlob);
    static CK_RV ReadBinaryFile(const std::string &filename, HsmPublicKeyBlob **ppBlob);

private:
    void _Init(const CK_VOID_PTR in, CK_ULONG inlen);
    void _Fini();
    static CK_RV _ReadBinaryFile(const std::string &filename, HsmBlob *ppBlob);

private:
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE_PTR pValue;
    CK_ULONG ulValueLen;
};

//
// HsmWrappedKeyBlob,
// HsmPublicKeyBlob,
//
// sub-class of HsmBlob
//

class HsmWrappedKeyBlob : public HsmBlob {
public:
    HsmWrappedKeyBlob(const CK_VOID_PTR in, CK_ULONG inlen) : HsmBlob(CKA_WRAPPED_KEY_BLOB, in, inlen) {}
    HsmWrappedKeyBlob(CK_ULONG inlen) : HsmBlob(CKA_WRAPPED_KEY_BLOB, NULL, inlen) {}
    virtual ~HsmWrappedKeyBlob() {}

    // unsafe copy constructor, assignment operator
    HsmWrappedKeyBlob(HsmWrappedKeyBlob &) : HsmBlob(0, 0, 0) { HSM_BUG(""); }
    HsmWrappedKeyBlob &operator=(HsmWrappedKeyBlob &) { HSM_BUG(""); }

public:
    CK_RV WriteJsonFile(const std::string &fileName, const std::string &SchemaVersion, const std::string &kid, const std::string &generator) const;
};

class HsmPublicKeyBlob : public HsmBlob {
public:
    HsmPublicKeyBlob(const CK_VOID_PTR in, CK_ULONG inlen) : HsmBlob(CKA_PUBLIC_KEY_BLOB, in, inlen) {}
    HsmPublicKeyBlob(CK_ULONG inlen) : HsmBlob(CKA_PUBLIC_KEY_BLOB, NULL, inlen) {}
    virtual ~HsmPublicKeyBlob() {}

    // unsafe copy constructor, assignment operator
    HsmPublicKeyBlob(HsmPublicKeyBlob &) : HsmBlob(0, 0, 0) { HSM_BUG(""); }
    HsmPublicKeyBlob &operator=(HsmPublicKeyBlob &) { HSM_BUG(""); }
};

//
// class HsmTemplate
//
// array of CK_ATTRIBUTE's
//

class HsmTemplate {
public:
    HsmTemplate(const CK_ATTRIBUTE_PTR in, CK_ULONG incount, bool for_reading = 0);
    HsmTemplate(bool for_reading = 0);
    virtual ~HsmTemplate();

    // unsafe copy constructor, assignment operator
    HsmTemplate(HsmTemplate &) { HSM_BUG(""); }
    HsmTemplate &operator=(HsmTemplate &) { HSM_BUG(""); }

public:
    const CK_ATTRIBUTE_PTR c_array() const { return array; }
    CK_ULONG c_count() const { return count; }

public:
    void SetOnce(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR p, CK_ULONG len);
    void SetOnce(CK_ATTRIBUTE_TYPE t, const std::string &sValue) {
        SetOnce(t, (CK_VOID_PTR)sValue.c_str(), (CK_ULONG)sValue.length());
    }
    void SetOnce(CK_ATTRIBUTE_TYPE t, CK_BBOOL bValue) { SetOnce(t, (CK_VOID_PTR) & bValue, sizeof(bValue)); }
    void SetOnce(CK_ATTRIBUTE_TYPE t, CK_ULONG ulValue) { SetOnce(t, (CK_VOID_PTR) & ulValue, sizeof(ulValue)); }

    void AppendOnce(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR p, CK_ULONG len);
    void AppendOnce(CK_ATTRIBUTE_TYPE t, const std::string &sValue) {
        AppendOnce(t, (CK_VOID_PTR)sValue.c_str(), (CK_ULONG)sValue.length());
    }
    void AppendOnce(CK_ATTRIBUTE_TYPE t, CK_BBOOL bValue) { AppendOnce(t, (CK_VOID_PTR) & bValue, sizeof(bValue)); }
    void AppendOnce(CK_ATTRIBUTE_TYPE t, CK_ULONG ulValue) { AppendOnce(t, (CK_VOID_PTR) & ulValue, sizeof(ulValue)); }

private:
    void _Init(const CK_ATTRIBUTE_PTR _array, CK_ULONG _count);
    void _Fini();

private:
    CK_ATTRIBUTE_PTR array;
    CK_ULONG count;
    bool flagReading;
    CK_ULONG allocatedCount;
};

#endif // _HSMUTILS_H
