extern crate pkcs11_sys;
#[macro_use]
extern crate lazy_static;

use pkcs11_sys::*;
mod unimplemented;
use std::mem;
use std::ptr;

lazy_static! {
    static ref FUNCTION_LIST : CK_FUNCTION_LIST = {
        CK_FUNCTION_LIST {
            version: CK_VERSION { major: 2, minor: 11 },
            C_Initialize: Some(C_Initialize),
            C_Finalize: Some(C_Finalize),
            C_GetInfo: Some(C_GetInfo),
            C_GetFunctionList: Some(C_GetFunctionList),
            C_GetSlotList: Some(unimplemented::C_GetSlotList),
            C_GetSlotInfo: Some(unimplemented::C_GetSlotInfo),
            C_GetTokenInfo: Some(unimplemented::C_GetTokenInfo),
            C_GetMechanismList: Some(unimplemented::C_GetMechanismList),
            C_GetMechanismInfo: Some(unimplemented::C_GetMechanismInfo),
            C_InitToken: Some(unimplemented::C_InitToken),
            C_InitPIN: Some(unimplemented::C_InitPIN),
            C_SetPIN: Some(unimplemented::C_SetPIN),
            C_OpenSession: Some(unimplemented::C_OpenSession),
            C_CloseSession: Some(unimplemented::C_CloseSession),
            C_CloseAllSessions: Some(unimplemented::C_CloseAllSessions),
            C_GetSessionInfo: Some(unimplemented::C_GetSessionInfo),
            C_GetOperationState: Some(unimplemented::C_GetOperationState),
            C_SetOperationState: Some(unimplemented::C_SetOperationState),
            C_Login: Some(unimplemented::C_Login),
            C_Logout: Some(unimplemented::C_Logout),
            C_CreateObject: Some(unimplemented::C_CreateObject),
            C_CopyObject: Some(unimplemented::C_CopyObject),
            C_DestroyObject: Some(unimplemented::C_DestroyObject),
            C_GetObjectSize: Some(unimplemented::C_GetObjectSize),
            C_GetAttributeValue: Some(unimplemented::C_GetAttributeValue),
            C_SetAttributeValue: Some(unimplemented::C_SetAttributeValue),
            C_FindObjectsInit: Some(unimplemented::C_FindObjectsInit),
            C_FindObjects: Some(unimplemented::C_FindObjects),
            C_FindObjectsFinal: Some(unimplemented::C_FindObjectsFinal),
            C_EncryptInit: Some(unimplemented::C_EncryptInit),
            C_Encrypt: Some(unimplemented::C_Encrypt),
            C_EncryptUpdate: Some(unimplemented::C_EncryptUpdate),
            C_EncryptFinal: Some(unimplemented::C_EncryptFinal),
            C_DecryptInit: Some(unimplemented::C_DecryptInit),
            C_Decrypt: Some(unimplemented::C_Decrypt),
            C_DecryptUpdate: Some(unimplemented::C_DecryptUpdate),
            C_DecryptFinal: Some(unimplemented::C_DecryptFinal),
            C_DigestInit: Some(unimplemented::C_DigestInit),
            C_Digest: Some(unimplemented::C_Digest),
            C_DigestUpdate: Some(unimplemented::C_DigestUpdate),
            C_DigestKey: Some(unimplemented::C_DigestKey),
            C_DigestFinal: Some(unimplemented::C_DigestFinal),
            C_SignInit: Some(unimplemented::C_SignInit),
            C_Sign: Some(unimplemented::C_Sign),
            C_SignUpdate: Some(unimplemented::C_SignUpdate),
            C_SignFinal: Some(unimplemented::C_SignFinal),
            C_SignRecoverInit: Some(unimplemented::C_SignRecoverInit),
            C_SignRecover: Some(unimplemented::C_SignRecover),
            C_VerifyInit: Some(unimplemented::C_VerifyInit),
            C_Verify: Some(unimplemented::C_Verify),
            C_VerifyUpdate: Some(unimplemented::C_VerifyUpdate),
            C_VerifyFinal: Some(unimplemented::C_VerifyFinal),
            C_VerifyRecoverInit: Some(unimplemented::C_VerifyRecoverInit),
            C_VerifyRecover: Some(unimplemented::C_VerifyRecover),
            C_DigestEncryptUpdate: Some(unimplemented::C_DigestEncryptUpdate),
            C_DecryptDigestUpdate: Some(unimplemented::C_DecryptDigestUpdate),
            C_SignEncryptUpdate: Some(unimplemented::C_SignEncryptUpdate),
            C_DecryptVerifyUpdate: Some(unimplemented::C_DecryptVerifyUpdate),
            C_GenerateKey: Some(unimplemented::C_GenerateKey),
            C_GenerateKeyPair: Some(unimplemented::C_GenerateKeyPair),
            C_WrapKey: Some(unimplemented::C_WrapKey),
            C_UnwrapKey: Some(unimplemented::C_UnwrapKey),
            C_DeriveKey: Some(unimplemented::C_DeriveKey),
            C_SeedRandom: Some(unimplemented::C_SeedRandom),
            C_GenerateRandom: Some(unimplemented::C_GenerateRandom),
            C_GetFunctionStatus: Some(unimplemented::C_GetFunctionStatus),
            C_CancelFunction: Some(unimplemented::C_CancelFunction),
            C_WaitForSlotEvent: Some(unimplemented::C_WaitForSlotEvent),

        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    CKR_OK as u64
}

#[no_mangle]
unsafe extern "C" fn C_Finalize(reserved: CK_VOID_PTR) -> CK_RV {
    CKR_OK as u64
}

#[no_mangle]
unsafe extern "C" fn C_GetInfo(infoptr: CK_INFO_PTR) -> CK_RV {
    let info: &mut CK_INFO = &mut *infoptr;
    info.cryptokiVersion = CK_VERSION {
        major: 1,
        minor: 10,
    };
    info.manufacturerID = [' ' as CK_UTF8CHAR; 32usize];
    let mid = "tarq-test";
    ptr::copy_nonoverlapping(mid.as_bytes().as_ptr(),
                             info.manufacturerID.as_mut_ptr(),
                             mid.len());
    info.libraryDescription = [' ' as CK_UTF8CHAR; 32usize];
    ptr::copy_nonoverlapping(mid.as_bytes().as_ptr(),
                             info.libraryDescription.as_mut_ptr(),
                             mid.len());
    info.libraryVersion = CK_VERSION { major: 0, minor: 1 };
    CKR_OK as u64
}

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    println!("IN FUNCTION LIST");
    *function_list = &(*FUNCTION_LIST) as *const CK_FUNCTION_LIST;
    CKR_OK as u64
}
