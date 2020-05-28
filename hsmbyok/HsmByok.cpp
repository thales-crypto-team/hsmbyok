/*****************************************************************************
*
* Copyright (c) 2019-2020 SafeNet. All rights reserved.
*
* This file contains information that is proprietary to SafeNet and may not be
* distributed or copied without written consent from SafeNet.
*
*****************************************************************************/

#include "HsmSecretKey.h"
#include "HsmKeyPair.h"
#include "HsmConfig.h"
#include "HsmUtils.h"
#include "HsmDefs.h"

#define HSM_BYOK_VERSION_SZ "1.0.0.3"

// function prototypes
CK_RV hsmbyok(int argc, char **argv);
CK_RV generate_vault_master_key();
CK_RV generate_and_wrap_target_key();
CK_RV unwrap_target_key();

// main function for hsm commands
int main(int argc, char **argv) {
    // copyright
    HsmUtil::Print("Copyright (c) 2019-2020 SafeNet. All rights reserved.\n\n");

    // version
    HsmUtil::Print("hsmbyok version " HSM_BYOK_VERSION_SZ ", " __DATE__ ", " __TIME__ "\n\n");

    // usage
    if (argc != 2) {
        HsmUtil::PrintError("usage: hsmbyok [option]\n");
        HsmUtil::Print("  where option is one of:\n\n");
#if defined(LUNA_HAVE_MASTER_KEY)
        HsmUtil::Print("    --generate-vault-master-key\n\n");
#endif
        HsmUtil::Print("    --generate-and-wrap-target-key\n\n");
#if defined(LUNA_HAVE_MASTER_KEY)
        HsmUtil::Print("    --unwrap-target-key\n\n");
#endif
        return -1;
    }

    CK_RV rv = CKR_FUNCTION_FAILED;

#if defined(_WIN32)
    rv = HsmConfig::InitFromIniFile(".\\HsmConfig.ini", "byok");
#else
    rv = HsmConfig::InitFromIniFile("./HsmConfig.ini", "byok");
#endif
    if (rv)
        goto done;

    rv = HsmApi::Init(HsmConfig::libraryName, HsmConfig::tokenLabel);
    if (rv)
        goto done;

    fprintf(stdout, "Enter password for Crypto-Officer: ");
    if (HsmSys::ReadPassword(HsmConfig::cryptoOfficerPin, sizeof(HsmConfig::cryptoOfficerPin)) < 7) {
        rv = CKR_PIN_INVALID;
        HsmApi::Fini();
        goto done;
    }

    rv = HsmApi::LoginCO(HsmConfig::cryptoOfficerPin);
    HsmConfig::ClearSensitiveParams();
    if (rv) {
        HsmApi::Fini();
        goto done;
    }

    rv = hsmbyok(argc, argv);

    HsmApi::Logout();
    HsmApi::Fini();

done:
    if (rv)
        HsmUtil::PrintError("overall failure", rv);
    else
        HsmUtil::PrintInfo("overall success");
    return rv ? 1 : 0;
}

// main function for hsmbyok command
CK_RV hsmbyok(int argc, char **argv) {
    char *option = argv[1];
    if (!HsmSys::strcasecmp(option, "--generate-vault-master-key")) {
        // pseudocode:
        //   generate masterKey keypair
        //   export masterKey public key
        return generate_vault_master_key();

    } else if (!HsmSys::strcasecmp(option, "--generate-and-wrap-target-key")) {
        // pseudocode:
        //   import temp masterKey public key
        //   generate temp rsa keypair
        //   generate temp aes key
        //   wrap temp aes with masterKey public (ie blob1)
        //   wrap temp rsa private with temp aes (ie blob2)
        //   concatenate blob1 || blob2
        //   test sign/encrypt
        return generate_and_wrap_target_key();

    } else if (!HsmSys::strcasecmp(option, "--unwrap-target-key")) {
        // pseudocode:
        //   unwrap temp aes with masterKey private
        //   unwrap temp rsa private with temp aes
        //   create temp rsa public
        //   test verify/decrypt
        return unwrap_target_key();
    }

    HsmUtil::PrintError("unrecognized option", (char *)option);
    return CKR_INVALID_COMMAND;
}

// generate master rsa keypair
CK_RV generate_vault_master_key() {
    CK_RV ckrv = CKR_FUNCTION_NOT_SUPPORTED;

#if defined(LUNA_HAVE_MASTER_KEY)
    HsmKeyPair *masterKey = new HsmKeyPair();
    HsmPublicKeyBlob *kekBlob = 0;

    CK_SESSION_HANDLE hSession = HsmApi::OpenSession();

    ckrv = masterKey->FindKeyPair(hSession, HsmConfig::masterKeyName);
    if (ckrv == CKR_OBJECT_NOT_FOUND) {
        if (HsmConfig::masterKeyFlags & CKF_CREATE_IF_NOT_FOUND) {
            HsmUtil::PrintWarning("masterKeyName not found - generating a new key", HsmConfig::masterKeyName);
            delete masterKey;
            masterKey = new HsmKeyPair();
            ckrv = masterKey->GenerateKeyPair(hSession, HsmConfig::masterKeySpec, HsmConfig::masterKeyName,
                                              HsmConfig::masterKeyFlags);
        }
    }

    if (ckrv == CKR_OBJECT_NOT_FOUND) {
        HsmUtil::PrintError("masterKeyName not found", HsmConfig::masterKeyName);
    } else if (ckrv == CKR_MULTIPLE_OBJECTS) {
        HsmUtil::PrintError("found multiple objects with the same masterKeyName", HsmConfig::masterKeyName);
    }

    if (ckrv == CKR_OK) {
        ckrv = masterKey->ExportPublicKey(hSession, &kekBlob);
    }

    if (ckrv == CKR_OK) {
        const std::string binFileName("kekBlob.bin");
        ckrv = HsmBlob::WriteBinaryFile(binFileName, kekBlob);
        HsmUtil::PrintInfo(binFileName.c_str(), ckrv);
    }

    // CloseSession AFTER deleting objects associated with session
    delete masterKey;
    delete kekBlob;
    HsmApi::CloseSession(hSession);
#endif // LUNA_HAVE_MASTER_KEY

    return ckrv;
}

// find/generate target key and wrap it using a copy of the master rsa public key
CK_RV generate_and_wrap_target_key() {
    CK_RV ckrv = CKR_FUNCTION_NOT_SUPPORTED;

    HsmKey *targetKey = 0;
    HsmWrappedKeyBlob *targetBlob = 0;

    CK_SESSION_HANDLE hSession = HsmApi::OpenSession();

    if (HsmConfig::WantSecretKeyTarget()) {
        HsmSecretKey *sk = new HsmSecretKey();
        ckrv = sk->FindSecretKey(hSession, HsmConfig::targetKeyName);
        if (ckrv == CKR_OBJECT_NOT_FOUND) {
            if (HsmConfig::targetKeyFlags & CKF_CREATE_IF_NOT_FOUND) {
                HsmUtil::PrintWarning("targetKeyName not found - generating a new key", HsmConfig::targetKeyName);
                delete sk;
                sk = new HsmSecretKey();
                ckrv = sk->GenerateSecretKey(hSession, HsmConfig::targetKeySpec, HsmConfig::targetKeyName,
                                             HsmConfig::targetKeyFlags);
            }
        }
        targetKey = sk;

    } else if (HsmConfig::WantKeyPairTarget()) {
        HsmKeyPair *kp = new HsmKeyPair();
        ckrv = kp->FindKeyPair(hSession, HsmConfig::targetKeyName);
        if (ckrv == CKR_OBJECT_NOT_FOUND) {
            if (HsmConfig::targetKeyFlags & CKF_CREATE_IF_NOT_FOUND) {
                HsmUtil::PrintWarning("targetKeyName not found - generating a new key", HsmConfig::targetKeyName);
                delete kp;
                kp = new HsmKeyPair();
                ckrv = kp->GenerateKeyPair(hSession, HsmConfig::targetKeySpec, HsmConfig::targetKeyName,
                                           HsmConfig::targetKeyFlags);
            }
        }
        targetKey = kp;

    } else {
        ckrv = CKR_KEY_TYPE_INCONSISTENT;
    }

    if (ckrv == CKR_OBJECT_NOT_FOUND) {
        HsmUtil::PrintError("targetKeyName not found", HsmConfig::targetKeyName);
    } else if (ckrv == CKR_MULTIPLE_OBJECTS) {
        HsmUtil::PrintError("found multiple objects with the same targetKeyName", HsmConfig::targetKeyName);
    }

    HsmKeyPair kek;

    if (ckrv == CKR_OK) {
        const std::string pemFileName("kekBlob.pem");
        ckrv = kek.ImportPublicKey(hSession, pemFileName);
        HsmUtil::PrintInfo(pemFileName.c_str(), ckrv);
#if defined(LUNA_HAVE_MASTER_KEY)
        if (ckrv == CKR_FILE_NOT_FOUND) {
            HsmPublicKeyBlob *kekBlob = 0;
            const std::string binFileName("kekBlob.bin");
            ckrv = HsmBlob::ReadBinaryFile(binFileName, &kekBlob);
            HsmUtil::PrintInfo(binFileName.c_str(), ckrv);
            if (ckrv == CKR_OK) {
                ckrv = kek.ImportPublicKey(hSession, kekBlob);
            }
            delete kekBlob;
        }
#endif // LUNA_HAVE_MASTER_KEY
    }

    if (ckrv == CKR_OK) {
        if (HsmConfig::WantWrapMethod1()) {
            ckrv = kek.WrapKeyMethod1(hSession, targetKey, &targetBlob);
        } else {
            ckrv = kek.WrapKeyMethod2(hSession, targetKey, &targetBlob);
        }
    }

#if defined(LUNA_HAVE_MASTER_KEY)
    if (ckrv == CKR_OK) {
        const std::string binFileName("targetBlob.bin");
        ckrv = HsmBlob::WriteBinaryFile(binFileName, targetBlob);
        HsmUtil::PrintInfo(binFileName.c_str(), ckrv);
    }
#endif // LUNA_HAVE_MASTER_KEY

    if (ckrv == CKR_OK) {
        std::string generator("hsmbyok " HSM_BYOK_VERSION_SZ "; ");
        generator += HsmApi::GetTokenInfo();
        const std::string jsonFileName("targetBlob.byok");
        ckrv = targetBlob->WriteJsonFile(jsonFileName, HsmConfig::SchemaVersion,
            HsmConfig::kid, generator);
        HsmUtil::PrintInfo(jsonFileName.c_str(), ckrv);
    }

#if defined(LUNA_HAVE_MASTER_KEY)
    // optionally encrypt some data to be verified when the key in unwrapped
    // NOTE: as of LUNA-14084 this has diminished value and this may confuse some customers;
    // however, let's keep it around for debugging only when LUNA_HAVE_MASTER_KEY is defined
    if (ckrv == CKR_OK) {
        const std::string str = "byok hello";
        const HsmBlob plaintext(str);
        HsmBlob *pEncrypted = 0;
        CK_RV rvtemp = targetKey->EncryptBlob(hSession, &plaintext, &pEncrypted);
        if (rvtemp == CKR_OK) {
            const std::string binFileName("targetBlob.enc");
            rvtemp = HsmBlob::WriteBinaryFile(binFileName, pEncrypted);
            HsmUtil::PrintInfo(binFileName.c_str(), rvtemp);
        }
        delete pEncrypted;
        HsmUtil::PrintInfo("sample encrypt", rvtemp);
    }
#endif

    // CloseSession AFTER deleting objects associated with session
    delete targetKey;
    delete targetBlob;
    HsmApi::CloseSession(hSession);

    return ckrv;
}

// unwrap target key blob using master rsa private key
CK_RV unwrap_target_key() {
    CK_RV ckrv = CKR_FUNCTION_NOT_SUPPORTED;

#if defined(LUNA_HAVE_MASTER_KEY)
    HsmWrappedKeyBlob *targetBlob = 0;
    HsmKeyPair *masterKey = new HsmKeyPair();
    HsmKey *unwrappedKey = 0;

    CK_SESSION_HANDLE hSession = HsmApi::OpenSession();

    const std::string binFileName("targetBlob.bin");
    ckrv = HsmBlob::ReadBinaryFile(binFileName, &targetBlob);
    HsmUtil::PrintInfo(binFileName.c_str(), ckrv);

    // find master key
    if (ckrv == CKR_OK) {
        ckrv = masterKey->FindKeyPair(hSession, HsmConfig::masterKeyName);
    }

    if (ckrv == CKR_OBJECT_NOT_FOUND) {
        HsmUtil::PrintError("masterKeyName not found", HsmConfig::masterKeyName);
    } else if (ckrv == CKR_MULTIPLE_OBJECTS) {
        HsmUtil::PrintError("found multiple objects with the same masterKeyName", HsmConfig::masterKeyName);
    }

    // unwrapped key should NOT exist
    if (ckrv == CKR_OK) {
        if (HsmConfig::WantSecretKeyUnwrapped()) {
            HsmSecretKey *sk = new HsmSecretKey();
            ckrv = sk->FindSecretKey(hSession, HsmConfig::unwrappedKeyName) == CKR_OBJECT_NOT_FOUND ? CKR_OK : CKR_OBJECT_EXISTS;
            delete sk;

        } else if (HsmConfig::WantKeyPairUnwrapped()) {
            HsmKeyPair *kp = new HsmKeyPair();
            ckrv = kp->FindKeyPair(hSession, HsmConfig::unwrappedKeyName) == CKR_OBJECT_NOT_FOUND ? CKR_OK : CKR_OBJECT_EXISTS;
            delete kp;

        } else {
            ckrv = CKR_KEY_TYPE_INCONSISTENT;
        }
    }

    // unwrap key
    if (ckrv == CKR_OK) {
        if (HsmConfig::WantWrapMethod1()) {
            ckrv = masterKey->UnwrapKeyMethod1(hSession, &unwrappedKey, targetBlob, HsmConfig::unwrappedKeySpec,
                                               HsmConfig::unwrappedKeyName, HsmConfig::unwrappedKeyFlags);
        } else {
            ckrv = masterKey->UnwrapKeyMethod2(hSession, &unwrappedKey, targetBlob, HsmConfig::unwrappedKeySpec,
                                               HsmConfig::unwrappedKeyName, HsmConfig::unwrappedKeyFlags);
        }
    }

    // optionally decrypt/verify some data
    if (ckrv == CKR_OK) {
        HsmBlob *pEncrypted = 0;
        const std::string binFileName("targetBlob.enc");
        CK_RV rvtemp = HsmBlob::ReadBinaryFile(binFileName, &pEncrypted);
        HsmUtil::PrintInfo(binFileName.c_str(), rvtemp);
        if (rvtemp == CKR_OK) {
            HsmBlob *pDecrypted = 0;
            rvtemp = unwrappedKey->DecryptBlob(hSession, pEncrypted, &pDecrypted);
            if (rvtemp == CKR_OK) {
                const std::string str = "byok hello";
                const HsmBlob plaintext(str);
                if (pDecrypted->Compare(plaintext)) {
                    rvtemp = CKR_DATA_INVALID;
                }
            }
            delete pDecrypted;
        }
        delete pEncrypted;
        HsmUtil::PrintInfo("sample decrypt", rvtemp);
    }

    // CloseSession AFTER deleting objects associated with session
    delete targetBlob;
    delete masterKey;
    delete unwrappedKey;
    HsmApi::CloseSession(hSession);
#endif // LUNA_HAVE_MASTER_KEY

    return ckrv;
}
