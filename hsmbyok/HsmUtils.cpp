/*****************************************************************************
*
* Copyright (c) 2019-2020 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent in SafeNet.
*
*****************************************************************************/

#include "HsmUtils.h"
#include "Base64.h"
#include "HsmSys.h"
#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>

//
// HsmUtil interface
//

// print a text message
// no newline char added
void HsmUtil::Print(const char *msg) {
    fprintf(stdout, "%s", msg);
    fflush(stdout);
}

// print a text message with optional prefix and return value
// add a newline char
void HsmUtil::PrintLine(const char *pre, const char *msg, CK_RV rv) {
    if (rv)
        fprintf(stdout, "%s: %s: %s (0x%08X)\n", pre, msg, HsmUtil::StringFromRV(rv), (unsigned)rv);
    else
        fprintf(stdout, "%s: %s\n", pre, msg);
    fflush(stdout);
}

// print a text message with optional prefix and return value
// add a newline char
void HsmUtil::PrintLine(const char *pre, const char *msg, const std::string& rv) {
    if (rv.length())
        fprintf(stdout, "%s: %s: %s\n", pre, msg, rv.c_str());
    else
        fprintf(stdout, "%s: %s\n", pre, msg);
    fflush(stdout);
}

// query type is a supported secret key type
bool HsmUtil::IsSecretKeyType(CK_KEY_TYPE type) {
    switch (type) {
    case CKK_AES:
        return true;
    case CKK_DES3:
        return true;
    }
    return false;
}

// query type is a supported keypair type
bool HsmUtil::IsKeyPairType(CK_KEY_TYPE type) {
    switch (type) {
    case CKK_RSA:
    case CKK_EC:
        return true;
    }
    return false;
}

// return maximum size of attribute type
// typically called when reading attribute values from hsm
CK_ULONG HsmUtil::GetMaxAttributeSize(CK_ATTRIBUTE_TYPE t) {
    // NOTE: missing attributes here leads to waste of allocated memory (no big deal)
    switch (t) {
    case CKA_LOCAL:
    case CKA_SENSITIVE:
    case CKA_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
        return sizeof(CK_BBOOL);

    case CKA_KEY_TYPE:
    case CKA_VALUE_LEN:
    case CKA_MODULUS_BITS:
        return sizeof(CK_ULONG);

    case CKA_LABEL:
        return CK_MAX_LABEL_BYTES;

    case CKA_MODULUS:
        return CK_MAX_MODULUS_BYTES;

    case CKA_PUBLIC_EXPONENT:
        return CK_MAX_PUBLIC_EXPONENT_BYTES;

    case CKA_EC_POINT:
        return CK_MAX_EC_POINT_BYTES;

    case CKA_EC_PARAMS:
        return CK_MAX_EC_PARAMS_BYTES;
    }

    return CK_MAX_VALUE_BYTES;
}

// convert string to corresponding CKK_* value
CK_KEY_TYPE HsmUtil::KeyTypeFromString(const char *szKeyType) {
    if (!HsmSys::strcasecmp(szKeyType, "CKK_RSA")) {
        return CKK_RSA;
    } else if (!HsmSys::strcasecmp(szKeyType, "CKK_EC")) {
        return CKK_EC;
    } else if (!HsmSys::strcasecmp(szKeyType, "CKK_AES")) {
        return CKK_AES;
    } else if (!HsmSys::strcasecmp(szKeyType, "CKK_DES3")) {
        return CKK_DES3;
    }
    return CK_INVALID_KEY_TYPE;
}

//
// HsmApi
//

HsmSys::HLIBRARY HsmApi::handle = 0;
CK_SLOT_ID HsmApi::slotId = CK_INVALID_SLOT_ID;
CK_SESSION_HANDLE HsmApi::hLoginSession = CK_INVALID_SESSION_HANDLE;
CK_FUNCTION_LIST_PTR HsmApi::FunctionList = NULL;
std::string HsmApi::szTokenInfo = "nolabel 255.255";

CK_RV HsmApi::Init(const char *libraryName, const char *tokenLabel) {
    CK_C_GetFunctionList C_GetFunctionList = NULL;
    HsmSys::HLIBRARY dl = HsmSys::dlopen(libraryName);
    if (dl == NULL) {
        HsmUtil::PrintError("dlopen");
        return CKR_LOAD_LIBRARY;
    }

    C_GetFunctionList = (CK_C_GetFunctionList)HsmSys::dlsym(dl, "C_GetFunctionList");
    if (C_GetFunctionList == NULL) {
        HsmSys::dlclose(dl);
        HsmUtil::PrintError("dlsym");
        return CKR_LOAD_LIBRARY_SYMBOL;
    }

    CK_RV rv = C_GetFunctionList(&FunctionList);
    if (rv != CKR_OK) {
        HsmSys::dlclose(dl);
        HsmUtil::PrintError("C_GetFunctionList", rv);
        return rv;
    }

    rv = FunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        HsmSys::dlclose(dl);
        HsmUtil::PrintError("C_Initialize", rv);
        return rv;
    }

    rv = FindSlotIdByLabel(tokenLabel);
    if (rv != CKR_OK) {
        HsmSys::dlclose(dl);
        HsmUtil::PrintError("FindSlotIdByLabel", rv);
        return rv;
    }

    handle = dl;
    return rv;
}

// find the first slotId with matching tokenLabel
CK_RV HsmApi::FindSlotIdByLabel(const char *inLabel) {
    CK_RV rv_find = CKR_TOKEN_NOT_FOUND;
    CK_RV rv = CKR_OK;
    CK_SLOT_ID_PTR pSlotList = 0;
    CK_ULONG ulCount = 0;
    const size_t inLabelLen = strlen(inLabel);
    CK_UTF8CHAR paddedLabel[32];
    CK_TOKEN_INFO info;
    if (rv == CKR_OK) {
        if (inLabelLen < 1 || inLabelLen > sizeof(paddedLabel) || (sizeof(info.label) != sizeof(paddedLabel)))
            rv = CKR_ARGUMENTS_BAD;
    }
    if (rv == CKR_OK) {
        memset(paddedLabel, ' ', sizeof(paddedLabel));
        memcpy(paddedLabel, inLabel, inLabelLen);
        rv = P11->C_GetSlotList(CK_TRUE, NULL, &ulCount);
    }
    if (rv == CKR_OK) {
        if (!ulCount)
            rv = CKR_ZERO_SLOTS;
    }
    if (rv == CKR_OK) {
        pSlotList = new CK_SLOT_ID[ulCount];
        if (!pSlotList)
            rv = CKR_HOST_MEMORY;
    }
    if (rv == CKR_OK) {
        rv = P11->C_GetSlotList(CK_TRUE, pSlotList, &ulCount);
    }
    if (rv == CKR_OK) {
        if (!ulCount)
            rv = CKR_ZERO_SLOTS;
    }
    if (rv == CKR_OK) {
        for (CK_ULONG i = 0; i < ulCount; i++) {
            memset(&info, 0, sizeof(info));
            rv = P11->C_GetTokenInfo(pSlotList[i], &info);
            if (rv == CKR_OK) {
                if (memcmp(paddedLabel, info.label, sizeof(paddedLabel)) == 0) {
                    slotId = pSlotList[i];
                    char tmpbuf[64] = {0};
                    snprintf(tmpbuf, sizeof(tmpbuf), "%s %u.%u", inLabel,
                        (unsigned)info.firmwareVersion.major,
                        (unsigned)info.firmwareVersion.minor);
                    szTokenInfo = tmpbuf;
                    rv_find = CKR_OK;
                    break;
                }
            }
        }
    }
    return rv_find;
}

void HsmApi::Fini() {
    if (FunctionList)
        FunctionList->C_Finalize(NULL);

    if (handle)
        (void)HsmSys::dlclose(handle);

    FunctionList = NULL;
    handle = 0;
}

// login as crypto-officer
CK_RV HsmApi::LoginCO(const char *coPin) {
    CK_CHAR_PTR pPin = (CK_CHAR_PTR)coPin;
    CK_ULONG ulPinLen = (CK_ULONG)strlen(coPin);
    CK_RV rv = P11->C_OpenSession(slotId, (CKF_RW_SESSION | CKF_SERIAL_SESSION), 0, 0, &hLoginSession);
    if (rv != CKR_OK)
        HsmUtil::PrintError("C_OpenSession", rv);
    if (rv == CKR_OK) {
        rv = P11->C_Login(hLoginSession, CKU_USER, pPin, ulPinLen);
        if (rv != CKR_OK)
            HsmUtil::PrintError("C_Login(CKU_USER)", rv);
    }
    return rv;
}

void HsmApi::Logout() {
    if (hLoginSession != CK_INVALID_SESSION_HANDLE) {
        (void)P11->C_Logout(hLoginSession);
        (void)P11->C_CloseSession(hLoginSession);
        hLoginSession = CK_INVALID_SESSION_HANDLE;
    }
}

CK_SESSION_HANDLE HsmApi::OpenSession() {
    CK_SESSION_HANDLE hSession = CK_INVALID_SESSION_HANDLE;
    if (P11->C_OpenSession(slotId, (CKF_RW_SESSION | CKF_SERIAL_SESSION), 0, 0, &hSession) != CKR_OK)
        hSession = CK_INVALID_SESSION_HANDLE;
    return hSession;
}

void HsmApi::CloseSession(CK_SESSION_HANDLE hSession) {
    if (hSession != CK_INVALID_SESSION_HANDLE)
        (void)P11->C_CloseSession(hSession);
}

//
// HsmBlob
//

HsmBlob::HsmBlob(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR in, CK_ULONG inlen) : type(t), pValue(0), ulValueLen(0) {
    _Init(in, inlen);
}

HsmBlob::HsmBlob(const CK_VOID_PTR in, CK_ULONG inlen) : type(CK_INVALID_TYPE), pValue(0), ulValueLen(0) {
    _Init(in, inlen);
}

HsmBlob::HsmBlob(CK_ULONG inlen) : type(CK_INVALID_TYPE), pValue(0), ulValueLen(0) {
    _Init(NULL, inlen);
}

HsmBlob::HsmBlob(const std::string &str) : type(CK_INVALID_TYPE), pValue(0), ulValueLen(0) {
    _Init((void *)str.c_str(), (CK_ULONG)str.length());
}

HsmBlob::~HsmBlob() { _Fini(); }

void HsmBlob::_Init(const CK_VOID_PTR in, CK_ULONG inlen) {
    pValue = (CK_BYTE_PTR)Duplicate(in, inlen);
    HSM_ASSERT(pValue);
    ulValueLen = inlen;
}

void HsmBlob::_Fini() {
    delete pValue;
    pValue = 0;
}

CK_VOID_PTR HsmBlob::Duplicate(const CK_VOID_PTR in, CK_ULONG inlen) {
    // allocate the minimum size if the input is unspecified
    const CK_ULONG allocated_len = inlen ? inlen : 8; // non-zero length
    HSM_ASSERT(allocated_len >= inlen);
    CK_BYTE_PTR p = new CK_BYTE[allocated_len];
    HSM_ASSERT(p);
    if (in)
        memcpy(p, in, inlen);
    else
        memset(p, 0, allocated_len);
    return p;
}

void HsmBlob::Concatenate(const HsmBlob &src) {
    const CK_ULONG totalLen = ulValueLen + src.ulValueLen;
    HSM_ASSERT(totalLen >= ulValueLen); // check overflow
    const CK_ULONG allocated_len = totalLen ? totalLen : 8; // non-zero length
    HSM_ASSERT(allocated_len >= totalLen);
    CK_BYTE_PTR p = new CK_BYTE[allocated_len];
    HSM_ASSERT(p);
    memcpy(p, pValue, ulValueLen);
    memcpy(p + ulValueLen, src.pValue, src.ulValueLen);
    delete pValue;
    pValue = p;
    ulValueLen = totalLen;
}

int HsmBlob::Compare(const HsmBlob &src) const {
    if (type != src.type)
        return -1;
    if (ulValueLen != src.ulValueLen)
        return -1;
    if (!pValue || !src.pValue)
        return -1;
    if (memcmp(pValue, src.pValue, ulValueLen) != 0)
        return 1;
    return 0;
}

CK_RV HsmBlob::WriteBinaryFile(const std::string &filename, const HsmBlob *pblob) {
    std::ofstream fs;
    fs.open(filename.c_str(), std::ofstream::binary | std::ofstream::out);
    if (!fs.is_open())
        return CKR_FILE_NOT_FOUND;
    CK_RV rv = CKR_FILE_IO;
    const CK_UINT32 u32type = (CK_UINT32)pblob->c_type();
    fs.write((char *)&u32type, sizeof(u32type));
    if (fs.good()) {
        fs.write((char *)pblob->c_value(), pblob->c_valueLen());
        if (fs.good()) {
            rv = CKR_OK;
        }
    }
    fs.close();
    return rv;
}

CK_ULONG HsmBlob::GetFileSize(const std::string &filename) {
    struct stat sbuf;
    int rc = stat(filename.c_str(), &sbuf);
    return rc == 0 ? sbuf.st_size : 0;
}

CK_RV HsmBlob::_ReadBinaryFile(const std::string &filename, HsmBlob *pblob) {
    std::ifstream fs;
    fs.open(filename.c_str(), std::ifstream::binary | std::ifstream::in);
    if (!fs.is_open())
        return CKR_FILE_NOT_FOUND;
    CK_RV rv = CKR_FILE_IO;
    CK_UINT32 u32type = (CK_UINT32)CK_INVALID_TYPE;
    if (fs.good()) {
        fs.read((char *)&u32type, sizeof(u32type));
        if (fs.good() && (u32type == pblob->type)) {
            fs.read((char *)pblob->pValue, pblob->ulValueLen);
            if (fs.good()) {
                rv = CKR_OK;
            }
        }
    }
    fs.close();
    return rv;
}

CK_RV HsmBlob::ReadBinaryFile(const std::string &filename, HsmBlob **ppBlob) {
    const CK_ULONG len = HsmBlob::GetFileSize(filename);
    if (len <= sizeof(CK_UINT32))
        return CKR_FILE_NOT_FOUND;
    HsmBlob *pblob = new HsmBlob(len - sizeof(CK_UINT32));
    if (!pblob)
        return CKR_HOST_MEMORY;
    CK_RV rv = _ReadBinaryFile(filename, pblob);
    if (rv == CKR_OK) {
        *ppBlob = pblob;
    } else {
        delete pblob;
    }
    return rv;
}

CK_RV HsmBlob::ReadBinaryFile(const std::string &filename, HsmWrappedKeyBlob **ppBlob) {
    const CK_ULONG len = HsmBlob::GetFileSize(filename);
    if (len <= sizeof(CK_UINT32))
        return CKR_FILE_NOT_FOUND;
    HsmWrappedKeyBlob *pblob = new HsmWrappedKeyBlob(len - sizeof(CK_UINT32));
    if (!pblob)
        return CKR_HOST_MEMORY;
    CK_RV rv = _ReadBinaryFile(filename, pblob);
    if (rv == CKR_OK) {
        *ppBlob = pblob;
    } else {
        delete pblob;
    }
    return rv;
}

CK_RV HsmBlob::ReadBinaryFile(const std::string &filename, HsmPublicKeyBlob **ppBlob) {
    const CK_ULONG len = HsmBlob::GetFileSize(filename);
    if (len <= sizeof(CK_UINT32))
        return CKR_FILE_NOT_FOUND;
    HsmPublicKeyBlob *pblob = new HsmPublicKeyBlob(len - sizeof(CK_UINT32));
    if (!pblob)
        return CKR_HOST_MEMORY;
    CK_RV rv = _ReadBinaryFile(filename, pblob);
    if (rv == CKR_OK) {
        *ppBlob = pblob;
    } else {
        delete pblob;
    }
    return rv;
}

// write json file in the format MS expects
CK_RV HsmWrappedKeyBlob::WriteJsonFile(const std::string &fileName, const std::string &SchemaVersion, const std::string &kid, const std::string &generator) const {
    std::ofstream fs;
    fs.open(fileName.c_str(), std::ofstream::out);
    if (!fs.is_open())
        return CKR_FILE_NOT_FOUND;
    CK_RV rv = CKR_FILE_IO;
    if (fs.good()) {
        // FIXME: assumes CKM_RSA_AES_KEY_WRAP_PAD
        std::string ciphertext;
        Base64::encodeURL(this->c_value(), this->c_valueLen(), ciphertext, false);
        fs << "{" << std::endl;
        // Changed "SchemaVersion" to "schema_version" to be more in line with JSON format
        fs << "  \"schema_version\": \"" << SchemaVersion << "\"," << std::endl;
        // Changed "protected" to "header" as there are no protected bits in that section
        fs << "  \"header\":" << std::endl;
        fs << "  {" << std::endl;
        fs << "    \"kid\": \"" << kid << "\"," << std::endl;
        fs << "    \"alg\": \"dir\"," << std::endl;
        fs << "    \"enc\": \"CKM_RSA_AES_KEY_WRAP\"" << std::endl;
        fs << "  }," << std::endl;
        // "ciphertext", with the value BASE64URL(JWE Ciphertext)
        fs << "  \"ciphertext\": \"" << ciphertext << "\"," << std::endl;
        fs << "  \"generator\": \"" << generator << "\"" << std::endl;
        fs << "}" << std::endl;
        if (fs.good()) {
            rv = CKR_OK;
        }
    }
    fs.close();
    return rv;
}

//
// HsmTemplate
//

HsmTemplate::HsmTemplate(const CK_ATTRIBUTE_PTR in, CK_ULONG incount, bool for_reading)
    : array(0), count(0), flagReading(for_reading), allocatedCount(0) {
    _Init(in, incount);
}

HsmTemplate::HsmTemplate(bool for_reading) : array(0), count(0), flagReading(for_reading), allocatedCount(0) {
    _Init(NULL, 15);
}

HsmTemplate::~HsmTemplate() { _Fini(); }

// allocate attribute values
void HsmTemplate::_Init(const CK_ATTRIBUTE_PTR in, CK_ULONG incount) {
    HSM_ASSERT(incount);

    allocatedCount = incount + 5;
    array = new CK_ATTRIBUTE[allocatedCount];
    HSM_ASSERT(array);

    CK_ULONG i = 0;

    if (in) {
        count = incount;
        for (; i < count; i++) {
            array[i].type = in[i].type;
            if (flagReading) {
                // allocate the maximum attribute size if the input size is unspecified
                const CK_ULONG allocated_len = in[i].ulValueLen ?
                                                       in[i].ulValueLen :
                                                       HsmUtil::GetMaxAttributeSize(in[i].type); // non-zero length
                array[i].pValue = HsmBlob::Duplicate(NULL, allocated_len);
                array[i].ulValueLen = allocated_len;
            } else {
                array[i].pValue = HsmBlob::Duplicate(in[i].pValue, in[i].ulValueLen);
                array[i].ulValueLen = in[i].ulValueLen;
            }
        }
    } else {
        count = 0;
    }

    for (; i < allocatedCount; i++) {
        array[i].type = CK_INVALID_TYPE;
        array[i].pValue = 0;
        array[i].ulValueLen = 0;
    }
}

// set attribute value once
// ie attribute type must be present however length must be invalid (zero)
void HsmTemplate::SetOnce(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR p, CK_ULONG len) {
    HSM_ASSERT(p && len);

    if (flagReading)
        HSM_BUG("template is read-only");

    for (CK_ULONG i = 0; i < count; i++) {
        if (array[i].type != t)
            continue;
        if (array[i].pValue && array[i].ulValueLen)
            HSM_BUGX("attribute type is already set", t);
        delete[]((CK_BYTE_PTR)array[i].pValue);
        array[i].pValue = HsmBlob::Duplicate(p, len);
        array[i].ulValueLen = len;
        return;
    }

    HSM_BUGX("attribute type is unexpected", t);
}

// append attribute value once
// ie attribute type must not be present
void HsmTemplate::AppendOnce(CK_ATTRIBUTE_TYPE t, const CK_VOID_PTR p, CK_ULONG len) {
    HSM_ASSERT(p && len);

    if (flagReading)
        HSM_BUG("template is read-only");

    CK_ULONG i = 0;
    for (; i < count; i++) {
        if (array[i].type == t)
            HSM_BUGX("attribute type is already set", t);
    }

    if (count < allocatedCount) {
        array[count].type = t;
        array[count].pValue = HsmBlob::Duplicate(p, len);
        array[count].ulValueLen = len;
        count++;
        return;
    }

    HSM_BUG("template is full");
}

// free attribute values
void HsmTemplate::_Fini() {
    if (array) {
        for (CK_ULONG i = 0; i < count; i++) {
            delete[]((CK_BYTE_PTR)array[i].pValue);
            array[i].type = 0;
            array[i].pValue = 0;
            array[i].ulValueLen = 0;
        }
        delete array;
    }

    array = 0;
    count = 0;
}

#include "LUNA/vendor_string.h"

// return string equivalent of CKR_* value
const char* HsmUtil::StringFromRV(CK_RV rv) {
    switch (rv) {
    CASE_DEFINE_TO_STR(CKR_OBJECT_NOT_FOUND);
    CASE_DEFINE_TO_STR(CKR_LOAD_LIBRARY);
    CASE_DEFINE_TO_STR(CKR_LOAD_LIBRARY_SYMBOL);
    CASE_DEFINE_TO_STR(CKR_FILE_NOT_FOUND);
    CASE_DEFINE_TO_STR(CKR_FILE_IO);
    CASE_DEFINE_TO_STR(CKR_INVALID_COMMAND);
    CASE_DEFINE_TO_STR(CKR_MULTIPLE_OBJECTS);
    CASE_DEFINE_TO_STR(CKR_ZERO_SLOTS);
    CASE_DEFINE_TO_STR(CKR_TOKEN_NOT_FOUND);
    CASE_DEFINE_TO_STR(CKR_OBJECT_EXISTS);
    }
    return GetErrorCode(rv);
}

// return string equivalent of CKK_* value
const char* HsmUtil::StringFromKeyType(CK_KEY_TYPE ckk) {
    return GetKeyType(ckk);
}
