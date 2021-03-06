#define CKR_INSERTION_CALLBACK_NOT_SUPPORTED 0x00000141
#define CKR_FUNCTION_PARALLEL                0x0052
#define CKR_SESSION_EXCLUSIVE_EXISTS         0x00B2
#define CKR_RC_ERROR                         (CKR_VENDOR_DEFINED + 0x04)
#define CKR_CONTAINER_HANDLE_INVALID         (CKR_VENDOR_DEFINED + 0x05)
#define CKR_TOO_MANY_CONTAINERS              (CKR_VENDOR_DEFINED + 0x06)
#define CKR_USER_LOCKED_OUT                  (CKR_VENDOR_DEFINED + 0x07)
#define CKR_CLONING_PARAMETER_ALREADY_EXISTS (CKR_VENDOR_DEFINED + 0x08)
#define CKR_CLONING_PARAMETER_MISSING        (CKR_VENDOR_DEFINED + 0x09)
#define CKR_CERTIFICATE_DATA_MISSING         (CKR_VENDOR_DEFINED + 0x0a)
#define CKR_CERTIFICATE_DATA_INVALID         (CKR_VENDOR_DEFINED + 0x0b)
#define CKR_ACCEL_DEVICE_ERROR               (CKR_VENDOR_DEFINED + 0x0c)
#define CKR_WRAPPING_ERROR                   (CKR_VENDOR_DEFINED + 0x0d)
#define CKR_UNWRAPPING_ERROR                 (CKR_VENDOR_DEFINED + 0x0e)
#define CKR_MAC_MISSING                      (CKR_VENDOR_DEFINED + 0x0f)
#define CKR_DAC_POLICY_PID_MISMATCH          (CKR_VENDOR_DEFINED + 0x10)
#define CKR_DAC_MISSING                      (CKR_VENDOR_DEFINED + 0x11)
#define CKR_BAD_DAC                          (CKR_VENDOR_DEFINED + 0x12)
#define CKR_SSK_MISSING                      (CKR_VENDOR_DEFINED + 0x13)
#define CKR_BAD_MAC                          (CKR_VENDOR_DEFINED + 0x14)
#define CKR_DAK_MISSING                      (CKR_VENDOR_DEFINED + 0x15)
#define CKR_BAD_DAK                          (CKR_VENDOR_DEFINED + 0x16)
#define CKR_SIM_AUTHORIZATION_FAILED         (CKR_VENDOR_DEFINED + 0x17)
#define CKR_SIM_VERSION_UNSUPPORTED          (CKR_VENDOR_DEFINED + 0x18)
#define CKR_SIM_CORRUPT_DATA                 (CKR_VENDOR_DEFINED + 0x19)
#define CKR_USER_NOT_AUTHORIZED              (CKR_VENDOR_DEFINED + 0x1a)
#define CKR_MAX_OBJECT_COUNT_EXCEEDED        (CKR_VENDOR_DEFINED + 0x1b)
#define CKR_SO_LOGIN_FAILURE_THRESHOLD       (CKR_VENDOR_DEFINED + 0x1c)
#define CKR_SIM_AUTHFORM_INVALID             (CKR_VENDOR_DEFINED + 0x1d)
#define CKR_CITS_DAK_MISSING                 (CKR_VENDOR_DEFINED + 0x1e)
#define CKR_UNABLE_TO_CONNECT                (CKR_VENDOR_DEFINED + 0x1f)
#define CKR_PARTITION_DISABLED               (CKR_VENDOR_DEFINED + 0x20)
#define CKR_CALLBACK_ERROR                   (CKR_VENDOR_DEFINED + 0x21)
#define CKR_SECURITY_PARAMETER_MISSING       (CKR_VENDOR_DEFINED + 0x22)
#define CKR_SP_TIMEOUT                       (CKR_VENDOR_DEFINED + 0x23)
#define CKR_TIMEOUT                          (CKR_VENDOR_DEFINED + 0x24)
#define CKR_ECC_UNKNOWN_CURVE                (CKR_VENDOR_DEFINED + 0x25)
#define CKR_MTK_ZEROIZED                     (CKR_VENDOR_DEFINED + 0x26)
#define CKR_MTK_STATE_INVALID                (CKR_VENDOR_DEFINED + 0x27)
#define CKR_INVALID_ENTRY_TYPE               (CKR_VENDOR_DEFINED + 0x28)
#define CKR_MTK_SPLIT_INVALID                (CKR_VENDOR_DEFINED + 0x29)
#define CKR_HSM_STORAGE_FULL                 (CKR_VENDOR_DEFINED + 0x2a)
#define CKR_DEVICE_TIMEOUT                   (CKR_VENDOR_DEFINED + 0x2b)
#define CKR_CONTAINER_OBJECT_STORAGE_FULL    (CKR_VENDOR_DEFINED + 0x2C)
#define CKR_PED_CLIENT_NOT_RUNNING           (CKR_VENDOR_DEFINED + 0x2D)
#define CKR_PED_UNPLUGGED                    (CKR_VENDOR_DEFINED + 0x2E)
#define CKR_ECC_POINT_INVALID                (CKR_VENDOR_DEFINED + 0x2F)
#define CKR_OPERATION_NOT_ALLOWED            (CKR_VENDOR_DEFINED + 0x30)
#define CKR_LICENSE_CAPACITY_EXCEEDED        (CKR_VENDOR_DEFINED + 0x31)
#define CKR_LOG_FILE_NOT_OPEN                (CKR_VENDOR_DEFINED + 0x32)
#define CKR_LOG_FILE_WRITE_ERROR             (CKR_VENDOR_DEFINED + 0x33)
#define CKR_LOG_BAD_FILE_NAME                (CKR_VENDOR_DEFINED + 0x34)
#define CKR_LOG_FULL                         (CKR_VENDOR_DEFINED + 0x35)
#define CKR_LOG_NO_KCV                       (CKR_VENDOR_DEFINED + 0x36)
#define CKR_LOG_BAD_RECORD_HMAC              (CKR_VENDOR_DEFINED + 0x37)
#define CKR_LOG_BAD_TIME                     (CKR_VENDOR_DEFINED + 0x38)
#define CKR_LOG_AUDIT_NOT_INITIALIZED        (CKR_VENDOR_DEFINED + 0x39)
#define CKR_LOG_RESYNC_NEEDED                (CKR_VENDOR_DEFINED + 0x3A)
#define CKR_AUDIT_LOGIN_TIMEOUT_IN_PROGRESS  (CKR_VENDOR_DEFINED + 0x3B)
#define CKR_AUDIT_LOGIN_FAILURE_THRESHOLD    (CKR_VENDOR_DEFINED + 0x3C)
#define CKR_INVALID_FUF_TARGET               (CKR_VENDOR_DEFINED + 0x3D)
#define CKR_INVALID_FUF_HEADER               (CKR_VENDOR_DEFINED + 0x3E)
#define CKR_INVALID_FUF_VERSION              (CKR_VENDOR_DEFINED + 0x3F)
#define CKR_ECC_ECC_RESULT_AT_INF            (CKR_VENDOR_DEFINED + 0x40)
#define CKR_AGAIN                            (CKR_VENDOR_DEFINED + 0x41)
#define CKR_TOKEN_COPIED                     (CKR_VENDOR_DEFINED + 0x42)
#define CKR_SLOT_NOT_EMPTY                   (CKR_VENDOR_DEFINED + 0x43)
#define CKR_USER_ALREADY_ACTIVATED           (CKR_VENDOR_DEFINED + 0x44)
#define CKR_STC_NO_CONTEXT                        (CKR_VENDOR_DEFINED + 0x45)
#define CKR_STC_CLIENT_IDENTITY_NOT_CONFIGURED    (CKR_VENDOR_DEFINED + 0x46)
#define CKR_STC_PARTITION_IDENTITY_NOT_CONFIGURED (CKR_VENDOR_DEFINED + 0x47)
#define CKR_STC_DH_KEYGEN_ERROR                   (CKR_VENDOR_DEFINED + 0x48)
#define CKR_STC_CIPHER_SUITE_REJECTED             (CKR_VENDOR_DEFINED + 0x49)
#define CKR_STC_DH_KEY_NOT_FROM_SAME_GROUP        (CKR_VENDOR_DEFINED + 0x4a)
#define CKR_STC_COMPUTE_DH_KEY_ERROR              (CKR_VENDOR_DEFINED + 0x4b)
#define CKR_STC_FIRST_PHASE_KDF_ERROR             (CKR_VENDOR_DEFINED + 0x4c)
#define CKR_STC_SECOND_PHASE_KDF_ERROR            (CKR_VENDOR_DEFINED + 0x4d)
#define CKR_STC_KEY_CONFIRMATION_FAILED           (CKR_VENDOR_DEFINED + 0x4e)
#define CKR_STC_NO_SESSION_KEY                    (CKR_VENDOR_DEFINED + 0x4f)
#define CKR_STC_RESPONSE_BAD_MAC                  (CKR_VENDOR_DEFINED + 0x50)
#define CKR_STC_NOT_ENABLED                       (CKR_VENDOR_DEFINED + 0x51)
#define CKR_STC_CLIENT_HANDLE_INVALID             (CKR_VENDOR_DEFINED + 0x52)
#define CKR_STC_SESSION_INVALID                   (CKR_VENDOR_DEFINED + 0x53)
#define CKR_STC_CONTAINER_INVALID                 (CKR_VENDOR_DEFINED + 0x54)
#define CKR_STC_SEQUENCE_NUM_INVALID              (CKR_VENDOR_DEFINED + 0x55)
#define CKR_STC_NO_CHANNEL                        (CKR_VENDOR_DEFINED + 0x56)
#define CKR_STC_RESPONSE_DECRYPT_ERROR            (CKR_VENDOR_DEFINED + 0x57)
#define CKR_STC_RESPONSE_REPLAYED                 (CKR_VENDOR_DEFINED + 0X58)
#define CKR_STC_REKEY_CHANNEL_MISMATCH            (CKR_VENDOR_DEFINED + 0X59)
#define CKR_STC_RSA_ENCRYPT_ERROR                 (CKR_VENDOR_DEFINED + 0X5a)
#define CKR_STC_RSA_SIGN_ERROR                    (CKR_VENDOR_DEFINED + 0X5b)
#define CKR_STC_RSA_DECRYPT_ERROR                 (CKR_VENDOR_DEFINED + 0X5c)
#define CKR_STC_RESPONSE_UNEXPECTED_KEY           (CKR_VENDOR_DEFINED + 0X5d)
#define CKR_STC_UNEXPECTED_NONCE_PAYLOAD_SIZE     (CKR_VENDOR_DEFINED + 0X5e)
#define CKR_STC_UNEXPECTED_DH_DATA_SIZE           (CKR_VENDOR_DEFINED + 0X5f)
#define CKR_STC_OPEN_CIPHER_MISMATCH              (CKR_VENDOR_DEFINED + 0X60)
#define CKR_STC_OPEN_DHNIST_PUBKEY_ERROR          (CKR_VENDOR_DEFINED + 0X61)
#define CKR_STC_OPEN_KEY_MATERIAL_GEN_FAIL        (CKR_VENDOR_DEFINED + 0X62)
#define CKR_STC_OPEN_RESP_GEN_FAIL                (CKR_VENDOR_DEFINED + 0X63)
#define CKR_STC_ACTIVATE_MACTAG_U_VERIFY_FAIL     (CKR_VENDOR_DEFINED + 0X64)
#define CKR_STC_ACTIVATE_MACTAG_V_GEN_FAIL        (CKR_VENDOR_DEFINED + 0X65)
#define CKR_STC_ACTIVATE_RESP_GEN_FAIL            (CKR_VENDOR_DEFINED + 0X66)
#define CKR_CHALLENGE_INCORRECT                   (CKR_VENDOR_DEFINED + 0X67)
#define CKR_ACCESS_ID_INVALID                     (CKR_VENDOR_DEFINED + 0X68)
#define CKR_ACCESS_ID_ALREADY_EXISTS              (CKR_VENDOR_DEFINED + 0X69)
#define CKR_KEY_NOT_KEKABLE                       (CKR_VENDOR_DEFINED + 0x6a)
#define CKR_MECHANISM_INVALID_FOR_FP              (CKR_VENDOR_DEFINED + 0x6b)
#define CKR_OPERATION_INVALID_FOR_FP              (CKR_VENDOR_DEFINED + 0x6c)
#define CKR_SESSION_HANDLE_INVALID_FOR_FP         (CKR_VENDOR_DEFINED + 0x6d)
#define CKR_CMD_NOT_ALLOWED_HSM_IN_TRANSPORT      (CKR_VENDOR_DEFINED + 0x6e)
#define CKR_OBJECT_ALREADY_EXISTS                 (CKR_VENDOR_DEFINED + 0X6f)
#define CKR_PARTITION_ROLE_DESC_VERSION_INVALID   (CKR_VENDOR_DEFINED + 0X70)
#define CKR_PARTITION_ROLE_POLICY_VERSION_INVALID (CKR_VENDOR_DEFINED + 0X71)
#define CKR_PARTITION_ROLE_POLICY_SET_VERSION_INVALID (CKR_VENDOR_DEFINED + 0X72)
#define CKR_REKEK_KEY                             (CKR_VENDOR_DEFINED + 0X73)
#define CKR_KEK_RETRY_FAILURE                     (CKR_VENDOR_DEFINED + 0X74)
#define CKR_RNG_RESEED_TOO_EARLY                  (CKR_VENDOR_DEFINED + 0X75)
#define CKR_HSM_TAMPERED                          (CKR_VENDOR_DEFINED + 0X76)
#define CKR_CONFIG_CHANGE_ILLEGAL                 (CKR_VENDOR_DEFINED + 0x77)
#define CKR_SESSION_CONTEXT_NOT_ALLOCATED         (CKR_VENDOR_DEFINED + 0x78)
#define CKR_SESSION_CONTEXT_ALREADY_ALLOCATED     (CKR_VENDOR_DEFINED + 0x79)
#define CKR_INVALID_BL_ITB_AUTH_HEADER            (CKR_VENDOR_DEFINED + 0x7A)
#define CKR_POLICY_ID_INVALID                     (CKR_VENDOR_DEFINED + 0x7B)
#define CKR_CONFIG_ILLEGAL                        (CKR_VENDOR_DEFINED + 0x7C)
#define CKR_CONFIG_FAILS_DEPENDENCIES             (CKR_VENDOR_DEFINED + 0x7D)
#define CKR_CERTIFICATE_TYPE_INVALID              (CKR_VENDOR_DEFINED + 0x7E)
#define CKR_INVALID_UTILIZATION_METRICS           (CKR_VENDOR_DEFINED + 0x7F)
#define CKR_UTILIZATION_BIN_ID_INVALID            (CKR_VENDOR_DEFINED + 0x80)
#define CKR_UTILIZATION_COUNTER_ID_INVALID        (CKR_VENDOR_DEFINED + 0x81)
#define CKR_INVALID_SERIAL_NUM                    (CKR_VENDOR_DEFINED + 0x82)
#define CKR_BIP32_CHILD_INDEX_INVALID             (CKR_VENDOR_DEFINED | 0x83)
#define CKR_BIP32_INVALID_HARDENED_DERIVATION     (CKR_VENDOR_DEFINED | 0x84)
#define CKR_BIP32_MASTER_SEED_LEN_INVALID         (CKR_VENDOR_DEFINED | 0x85)
#define CKR_BIP32_MASTER_SEED_INVALID             (CKR_VENDOR_DEFINED | 0x86)
#define CKR_BIP32_INVALID_KEY_PATH_LEN            (CKR_VENDOR_DEFINED | 0x87)
#define CKR_FM_ID_INVALID                         (CKR_VENDOR_DEFINED + 0x88)
#define CKR_FM_NOT_SUPPORTED                      (CKR_VENDOR_DEFINED + 0x89)
#define CKR_FM_NEVER_ENABLED                      (CKR_VENDOR_DEFINED + 0x8a)
#define CKR_FM_DISABLED                           (CKR_VENDOR_DEFINED + 0x8b)
#define CKR_FM_SMFS_INACTIVE                      (CKR_VENDOR_DEFINED + 0x8c)
#define CKR_HSM_RESTART_REQUIRED                  (CKR_VENDOR_DEFINED + 0x8d)
#define CKR_FM_CFG_ALLOWEDFLAG_DISABLED           (CKR_VENDOR_DEFINED + 0x8e)
#define CKR_OBJECT_READ_ONLY                 (CKR_VENDOR_DEFINED + 0x114)
#define CKR_KEY_NOT_ACTIVE                   (CKR_VENDOR_DEFINED + 0x136)
