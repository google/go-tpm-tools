/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _NV_SPT_FP_H_
#define _NV_SPT_FP_H_

//*** NvReadAccessChecks()
// Common routine for validating a read
// Used by TPM2_NV_Read, TPM2_NV_ReadLock and TPM2_PolicyNV
//  Return Type: TPM_RC
//      TPM_RC_NV_AUTHORIZATION     autHandle is not allowed to authorize read
//                                  of the index
//      TPM_RC_NV_LOCKED            Read locked
//      TPM_RC_NV_UNINITIALIZED     Try to read an uninitialized index
//
TPM_RC
NvReadAccessChecks(TPM_HANDLE authHandle,  // IN: the handle that provided the
                                           //     authorization
                   TPM_HANDLE nvHandle,   // IN: the handle of the NV index to be read
                   TPMA_NV    attributes  // IN: the attributes of 'nvHandle'
);

//*** NvWriteAccessChecks()
// Common routine for validating a write
// Used by TPM2_NV_Write, TPM2_NV_Increment, TPM2_SetBits, and TPM2_NV_WriteLock
//  Return Type: TPM_RC
//      TPM_RC_NV_AUTHORIZATION     Authorization fails
//      TPM_RC_NV_LOCKED            Write locked
//
TPM_RC
NvWriteAccessChecks(
    TPM_HANDLE authHandle,  // IN: the handle that provided the
                            //     authorization
    TPM_HANDLE nvHandle,    // IN: the handle of the NV index to be written
    TPMA_NV    attributes   // IN: the attributes of 'nvHandle'
);

//*** NvReadOnlyModeChecks()
// Common routine to verify whether an NV command is allowed on an index
// with the given 'attributes' while the TPM is in Read-Only mode
// Used by TPM2_NV_Write, TPM2_NV_Extend, TPM2_SetBits, TPM2_NV_WriteLock
// and TPM2_NV_ReadLock
//  Return Type: TPM_RC
//      TPM_RC_SUCCESS     The command is allowed
//      TPM_RC_READ_ONLY   The TPM is in Read-Only mode and the command is
//                         not allowed
//
TPM_RC
NvReadOnlyModeChecks(TPMA_NV attributes  // IN: the attributes of the index to check
);

//*** NvClearOrderly()
// This function is used to cause gp.orderlyState to be cleared to the
// non-orderly state.
TPM_RC
NvClearOrderly(void);

//*** NvIsPinPassIndex()
// Function to check to see if an NV index is a PIN Pass Index
//  Return Type: BOOL
//      TRUE(1)         is pin pass
//      FALSE(0)        is not pin pass
BOOL NvIsPinPassIndex(TPM_HANDLE index  // IN: Handle to check
);

//*** NvIsPinCountedIndex()
// Function to check to see if an NV index is either a PIN Pass
// or a PIN FAIL Index
//  Return Type: BOOL
//      TRUE(1)         is pin pass or pin fail
//      FALSE(0)        is neither pin pass nor pin fail
BOOL NvIsPinCountedIndex(TPM_HANDLE index  // IN: Handle to check
);

//*** NvGetIndexName()
// This function computes the Name of an index
// The 'name' buffer receives the bytes of the Name and the return value
// is the number of octets in the Name.
//
// This function requires that the NV Index is defined.
TPM2B_NAME* NvGetIndexName(
    NV_INDEX* nvIndex,  // IN: the index over which the name is to be
                        //     computed
    TPM2B_NAME* name    // OUT: name of the index
);

//*** NvPublic2FromNvPublic()
// This function converts a legacy-form NV public (TPMS_NV_PUBLIC) into the
// generalized TPMT_NV_PUBLIC_2 tagged-union representation.
TPM_RC NvPublic2FromNvPublic(
    TPMS_NV_PUBLIC*   nvPublic,  // IN: the source S-form NV public area
    TPMT_NV_PUBLIC_2* nvPublic2  // OUT: the T-form NV public area to populate
);

//*** NvPublicFromNvPublic2()
// This function converts a tagged-union NV public (TPMT_NV_PUBLIC_2) into the
// legacy TPMS_NV_PUBLIC representation. This is a lossy conversion: any
// bits in the extended area of the attributes are lost, and the Name cannot be
// computed based on it.
TPM_RC NvPublicFromNvPublic2(
    TPMT_NV_PUBLIC_2* nvPublic2,  // IN: the source T-form NV public area
    TPMS_NV_PUBLIC*   nvPublic    // OUT: the S-form NV public area to populate
);

//*** NvDefineSpace()
// This function combines the common functionality of TPM2_NV_DefineSpace and
// TPM2_NV_DefineSpace2.
TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle,
                     TPM2B_AUTH*       auth,
                     TPMS_NV_PUBLIC*   publicInfo,
                     TPM_RC            blameAuthHandle,
                     TPM_RC            blameAuth,
                     TPM_RC            blamePublic);

#endif  // _NV_SPT_FP_H_
