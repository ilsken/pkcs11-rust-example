use pkcs11_sys::*;


pub unsafe extern "C" fn C_GetSlotList(tokenPresent: CK_BBOOL,
                                       pSlotList: CK_SLOT_ID_PTR,
                                       pulCount: CK_ULONG_PTR)
                                       -> CK_RV {
    if !pSlotList.is_null() {
        *pSlotList = 1;
    }
    *pulCount = 1;
    CKR_OK as u64
}


pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if slotID != 1 {
        return CKR_SLOT_ID_INVALID as u64;
    }
    let info: &mut CK_TOKEN_INFO = &mut *pInfo;
    let mid = "tarq-test";
    info.label = [' ' as CK_UTF8CHAR; 32usize];
    info.manufacturerID = [' ' as CK_UTF8CHAR; 32usize];
    info.model = [' ' as CK_UTF8CHAR; 16usize];
    info.serialNumber = [' ' as CK_UTF8CHAR; 16usize];
    info.flags = (CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED |
                  CKF_PROTECTED_AUTHENTICATION_PATH) as u64;
    info.ulMaxSessionCount = 5;
    info.ulSessionCount = 1;
    info.ulMaxRwSessionCount = 5;
    info.ulRwSessionCount = 1;
    info.ulMaxPinLen = 1024;
    info.ulMinPinLen = 0;
    info.ulTotalPublicMemory = 47120;
    info.ulFreePublicMemory = 47110;
    info.ulTotalPrivateMemory = 47140;
    info.ulFreePrivateMemory = 47130;
    info.hardwareVersion.major = 2;
    info.hardwareVersion.minor = 0;
    info.firmwareVersion.major = 2;
    info.firmwareVersion.minor = 0;
    CKR_OK as u64


}


pub unsafe extern "C" fn C_GetMechanismList(slotID: CK_SLOT_ID,
                                            pMechanismList: CK_MECHANISM_TYPE_PTR,
                                            pulCount: CK_ULONG_PTR)
                                            -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetMechanismInfo(slotID: CK_SLOT_ID,
                                            type_: CK_MECHANISM_TYPE,
                                            pInfo: CK_MECHANISM_INFO_PTR)
                                            -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_InitToken(slotID: CK_SLOT_ID,
                                     pPin: CK_UTF8CHAR_PTR,
                                     ulPinLen: CK_ULONG,
                                     pLabel: CK_UTF8CHAR_PTR)
                                     -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_InitPIN(hSession: CK_SESSION_HANDLE,
                                   pPin: CK_UTF8CHAR_PTR,
                                   ulPinLen: CK_ULONG)
                                   -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SetPIN(hSession: CK_SESSION_HANDLE,
                                  pOldPin: CK_UTF8CHAR_PTR,
                                  ulOldLen: CK_ULONG,
                                  pNewPin: CK_UTF8CHAR_PTR,
                                  ulNewLen: CK_ULONG)
                                  -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_OpenSession(slotID: CK_SLOT_ID,
                                       flags: CK_FLAGS,
                                       pApplication: CK_VOID_PTR,
                                       Notify: CK_NOTIFY,
                                       phSession: CK_SESSION_HANDLE_PTR)
                                       -> CK_RV {
    if (slotID != 1) {
        return CKR_SLOT_ID_INVALID as u64;
    }
    CKR_OK as u64
}


pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE,
                                          pInfo: CK_SESSION_INFO_PTR)
                                          -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetOperationState(hSession: CK_SESSION_HANDLE,
                                             pOperationState: CK_BYTE_PTR,
                                             pulOperationStateLen: CK_ULONG_PTR)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SetOperationState(hSession: CK_SESSION_HANDLE,
                                             pOperationState: CK_BYTE_PTR,
                                             ulOperationStateLen: CK_ULONG,
                                             hEncryptionKey: CK_OBJECT_HANDLE,
                                             hAuthenticationKey: CK_OBJECT_HANDLE)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Login(hSession: CK_SESSION_HANDLE,
                                 userType: CK_USER_TYPE,
                                 pPin: CK_UTF8CHAR_PTR,
                                 ulPinLen: CK_ULONG)
                                 -> CK_RV {
    println!("IN LOGIN");
    CKR_OK as CK_RV
}


pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_CreateObject(hSession: CK_SESSION_HANDLE,
                                        pTemplate: CK_ATTRIBUTE_PTR,
                                        ulCount: CK_ULONG,
                                        phObject: CK_OBJECT_HANDLE_PTR)
                                        -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_CopyObject(hSession: CK_SESSION_HANDLE,
                                      hObject: CK_OBJECT_HANDLE,
                                      pTemplate: CK_ATTRIBUTE_PTR,
                                      ulCount: CK_ULONG,
                                      phNewObject: CK_OBJECT_HANDLE_PTR)
                                      -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE,
                                         hObject: CK_OBJECT_HANDLE)
                                         -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetObjectSize(hSession: CK_SESSION_HANDLE,
                                         hObject: CK_OBJECT_HANDLE,
                                         pulSize: CK_ULONG_PTR)
                                         -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetAttributeValue(hSession: CK_SESSION_HANDLE,
                                             hObject: CK_OBJECT_HANDLE,
                                             pTemplate: CK_ATTRIBUTE_PTR,
                                             ulCount: CK_ULONG)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SetAttributeValue(hSession: CK_SESSION_HANDLE,
                                             hObject: CK_OBJECT_HANDLE,
                                             pTemplate: CK_ATTRIBUTE_PTR,
                                             ulCount: CK_ULONG)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_FindObjectsInit(hSession: CK_SESSION_HANDLE,
                                           pTemplate: CK_ATTRIBUTE_PTR,
                                           ulCount: CK_ULONG)
                                           -> CK_RV {
    CKR_OK as u64
}


pub unsafe extern "C" fn C_FindObjects(hSession: CK_SESSION_HANDLE,
                                       phObject: CK_OBJECT_HANDLE_PTR,
                                       ulMaxObjectCount: CK_ULONG,
                                       pulObjectCount: CK_ULONG_PTR)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_EncryptInit(hSession: CK_SESSION_HANDLE,
                                       pMechanism: CK_MECHANISM_PTR,
                                       hKey: CK_OBJECT_HANDLE)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Encrypt(hSession: CK_SESSION_HANDLE,
                                   pData: CK_BYTE_PTR,
                                   ulDataLen: CK_ULONG,
                                   pEncryptedData: CK_BYTE_PTR,
                                   pulEncryptedDataLen: CK_ULONG_PTR)
                                   -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_EncryptUpdate(hSession: CK_SESSION_HANDLE,
                                         pPart: CK_BYTE_PTR,
                                         ulPartLen: CK_ULONG,
                                         pEncryptedPart: CK_BYTE_PTR,
                                         pulEncryptedPartLen: CK_ULONG_PTR)
                                         -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_EncryptFinal(hSession: CK_SESSION_HANDLE,
                                        pLastEncryptedPart: CK_BYTE_PTR,
                                        pulLastEncryptedPartLen: CK_ULONG_PTR)
                                        -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DecryptInit(hSession: CK_SESSION_HANDLE,
                                       pMechanism: CK_MECHANISM_PTR,
                                       hKey: CK_OBJECT_HANDLE)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Decrypt(hSession: CK_SESSION_HANDLE,
                                   pEncryptedData: CK_BYTE_PTR,
                                   ulEncryptedDataLen: CK_ULONG,
                                   pData: CK_BYTE_PTR,
                                   pulDataLen: CK_ULONG_PTR)
                                   -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DecryptUpdate(hSession: CK_SESSION_HANDLE,
                                         pEncryptedPart: CK_BYTE_PTR,
                                         ulEncryptedPartLen: CK_ULONG,
                                         pPart: CK_BYTE_PTR,
                                         pulPartLen: CK_ULONG_PTR)
                                         -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DecryptFinal(hSession: CK_SESSION_HANDLE,
                                        pLastPart: CK_BYTE_PTR,
                                        pulLastPartLen: CK_ULONG_PTR)
                                        -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DigestInit(hSession: CK_SESSION_HANDLE,
                                      pMechanism: CK_MECHANISM_PTR)
                                      -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Digest(hSession: CK_SESSION_HANDLE,
                                  pData: CK_BYTE_PTR,
                                  ulDataLen: CK_ULONG,
                                  pDigest: CK_BYTE_PTR,
                                  pulDigestLen: CK_ULONG_PTR)
                                  -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DigestUpdate(hSession: CK_SESSION_HANDLE,
                                        pPart: CK_BYTE_PTR,
                                        ulPartLen: CK_ULONG)
                                        -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DigestFinal(hSession: CK_SESSION_HANDLE,
                                       pDigest: CK_BYTE_PTR,
                                       pulDigestLen: CK_ULONG_PTR)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignInit(hSession: CK_SESSION_HANDLE,
                                    pMechanism: CK_MECHANISM_PTR,
                                    hKey: CK_OBJECT_HANDLE)
                                    -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Sign(hSession: CK_SESSION_HANDLE,
                                pData: CK_BYTE_PTR,
                                ulDataLen: CK_ULONG,
                                pSignature: CK_BYTE_PTR,
                                pulSignatureLen: CK_ULONG_PTR)
                                -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignUpdate(hSession: CK_SESSION_HANDLE,
                                      pPart: CK_BYTE_PTR,
                                      ulPartLen: CK_ULONG)
                                      -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignFinal(hSession: CK_SESSION_HANDLE,
                                     pSignature: CK_BYTE_PTR,
                                     pulSignatureLen: CK_ULONG_PTR)
                                     -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignRecoverInit(hSession: CK_SESSION_HANDLE,
                                           pMechanism: CK_MECHANISM_PTR,
                                           hKey: CK_OBJECT_HANDLE)
                                           -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignRecover(hSession: CK_SESSION_HANDLE,
                                       pData: CK_BYTE_PTR,
                                       ulDataLen: CK_ULONG,
                                       pSignature: CK_BYTE_PTR,
                                       pulSignatureLen: CK_ULONG_PTR)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_VerifyInit(hSession: CK_SESSION_HANDLE,
                                      pMechanism: CK_MECHANISM_PTR,
                                      hKey: CK_OBJECT_HANDLE)
                                      -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_Verify(hSession: CK_SESSION_HANDLE,
                                  pData: CK_BYTE_PTR,
                                  ulDataLen: CK_ULONG,
                                  pSignature: CK_BYTE_PTR,
                                  ulSignatureLen: CK_ULONG)
                                  -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_VerifyUpdate(hSession: CK_SESSION_HANDLE,
                                        pPart: CK_BYTE_PTR,
                                        ulPartLen: CK_ULONG)
                                        -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_VerifyFinal(hSession: CK_SESSION_HANDLE,
                                       pSignature: CK_BYTE_PTR,
                                       ulSignatureLen: CK_ULONG)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_VerifyRecoverInit(hSession: CK_SESSION_HANDLE,
                                             pMechanism: CK_MECHANISM_PTR,
                                             hKey: CK_OBJECT_HANDLE)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_VerifyRecover(hSession: CK_SESSION_HANDLE,
                                         pSignature: CK_BYTE_PTR,
                                         ulSignatureLen: CK_ULONG,
                                         pData: CK_BYTE_PTR,
                                         pulDataLen: CK_ULONG_PTR)
                                         -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DigestEncryptUpdate(hSession: CK_SESSION_HANDLE,
                                               pPart: CK_BYTE_PTR,
                                               ulPartLen: CK_ULONG,
                                               pEncryptedPart: CK_BYTE_PTR,
                                               pulEncryptedPartLen: CK_ULONG_PTR)
                                               -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DecryptDigestUpdate(hSession: CK_SESSION_HANDLE,
                                               pEncryptedPart: CK_BYTE_PTR,
                                               ulEncryptedPartLen: CK_ULONG,
                                               pPart: CK_BYTE_PTR,
                                               pulPartLen: CK_ULONG_PTR)
                                               -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SignEncryptUpdate(hSession: CK_SESSION_HANDLE,
                                             pPart: CK_BYTE_PTR,
                                             ulPartLen: CK_ULONG,
                                             pEncryptedPart: CK_BYTE_PTR,
                                             pulEncryptedPartLen: CK_ULONG_PTR)
                                             -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DecryptVerifyUpdate(hSession: CK_SESSION_HANDLE,
                                               pEncryptedPart: CK_BYTE_PTR,
                                               ulEncryptedPartLen: CK_ULONG,
                                               pPart: CK_BYTE_PTR,
                                               pulPartLen: CK_ULONG_PTR)
                                               -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GenerateKey(hSession: CK_SESSION_HANDLE,
                                       pMechanism: CK_MECHANISM_PTR,
                                       pTemplate: CK_ATTRIBUTE_PTR,
                                       ulCount: CK_ULONG,
                                       phKey: CK_OBJECT_HANDLE_PTR)
                                       -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GenerateKeyPair(hSession: CK_SESSION_HANDLE,
                                           pMechanism: CK_MECHANISM_PTR,
                                           pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
                                           ulPublicKeyAttributeCount: CK_ULONG,
                                           pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
                                           ulPrivateKeyAttributeCount: CK_ULONG,
                                           phPublicKey: CK_OBJECT_HANDLE_PTR,
                                           phPrivateKey: CK_OBJECT_HANDLE_PTR)
                                           -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_WrapKey(hSession: CK_SESSION_HANDLE,
                                   pMechanism: CK_MECHANISM_PTR,
                                   hWrappingKey: CK_OBJECT_HANDLE,
                                   hKey: CK_OBJECT_HANDLE,
                                   pWrappedKey: CK_BYTE_PTR,
                                   pulWrappedKeyLen: CK_ULONG_PTR)
                                   -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_UnwrapKey(hSession: CK_SESSION_HANDLE,
                                     pMechanism: CK_MECHANISM_PTR,
                                     hUnwrappingKey: CK_OBJECT_HANDLE,
                                     pWrappedKey: CK_BYTE_PTR,
                                     ulWrappedKeyLen: CK_ULONG,
                                     pTemplate: CK_ATTRIBUTE_PTR,
                                     ulAttributeCount: CK_ULONG,
                                     phKey: CK_OBJECT_HANDLE_PTR)
                                     -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_DeriveKey(hSession: CK_SESSION_HANDLE,
                                     pMechanism: CK_MECHANISM_PTR,
                                     hBaseKey: CK_OBJECT_HANDLE,
                                     pTemplate: CK_ATTRIBUTE_PTR,
                                     ulAttributeCount: CK_ULONG,
                                     phKey: CK_OBJECT_HANDLE_PTR)
                                     -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_SeedRandom(hSession: CK_SESSION_HANDLE,
                                      pSeed: CK_BYTE_PTR,
                                      ulSeedLen: CK_ULONG)
                                      -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GenerateRandom(hSession: CK_SESSION_HANDLE,
                                          RandomData: CK_BYTE_PTR,
                                          ulRandomLen: CK_ULONG)
                                          -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_CancelFunction(hSession: CK_SESSION_HANDLE) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}


pub unsafe extern "C" fn C_WaitForSlotEvent(flags: CK_FLAGS,
                                            pSlot: CK_SLOT_ID_PTR,
                                            pRserved: CK_VOID_PTR)
                                            -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}
