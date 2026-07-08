/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar  4, 2020  Time: 02:36:44PM
 */

#ifndef _PCR_FP_H_
#define _PCR_FP_H_

//*** PCRBelongsAuthGroup()
// This function indicates if a PCR belongs to a group that requires an authValue
// in order to modify the PCR.  If it does, 'groupIndex' is set to value of
// the group index.  This feature of PCR is decided by the platform specification.
//
//  Return Type: BOOL
//      TRUE(1)         PCR belongs an authorization group
//      FALSE(0)        PCR does not belong an authorization group
BOOL PCRBelongsAuthGroup(TPMI_DH_PCR handle,     // IN: handle of PCR
                         UINT32*     groupIndex  // OUT: group index if PCR belongs a
                         //      group that allows authValue.  If PCR
                         //      does not belong to an authorization
                         //      group, the value in this parameter is
                         //      invalid
);

//*** PCRBelongsPolicyGroup()
// This function indicates if a PCR belongs to a group that requires a policy
// authorization in order to modify the PCR.  If it does, 'groupIndex' is set
// to value of the group index.  This feature of PCR is decided by the platform
// specification.
//
//  Return Type: BOOL
//      TRUE(1)         PCR belongs to a policy group
//      FALSE(0)        PCR does not belong to a policy group
BOOL PCRBelongsPolicyGroup(
    TPMI_DH_PCR handle,     // IN: handle of PCR
    UINT32*     groupIndex  // OUT: group index if PCR belongs a group that
                            //     allows policy.  If PCR does not belong to
                            //     a policy group, the value in this
                            //     parameter is invalid
);

//*** PCRPolicyIsAvailable()
// This function indicates if a policy is available for a PCR.
//
//  Return Type: BOOL
//      TRUE(1)         the PCR may be authorized by policy
//      FALSE(0)        the PCR does not allow policy
BOOL PCRPolicyIsAvailable(TPMI_DH_PCR handle  // IN: PCR handle
);

//*** PCRGetAuthValue()
// This function is used to access the authValue of a PCR.  If PCR does not
// belong to an authValue group, an EmptyAuth will be returned.
TPM2B_AUTH* PCRGetAuthValue(TPMI_DH_PCR handle  // IN: PCR handle
);

//*** PCRGetAuthPolicy()
// This function is used to access the authorization policy of a PCR. It sets
// 'policy' to the authorization policy and returns the hash algorithm for policy
//  If the PCR does not allow a policy, TPM_ALG_NULL is returned.
TPMI_ALG_HASH
PCRGetAuthPolicy(TPMI_DH_PCR   handle,  // IN: PCR handle
                 TPM2B_DIGEST* policy   // OUT: policy of PCR
);

//*** PCRManufacture()
// This function is used to initialize the policies when a TPM is manufactured.
// This function would only be called in a manufacturing environment or in
// a TPM simulator.
void PCRManufacture(void);

//*** PcrIsAllocated()
// This function indicates if a PCR number for the particular hash algorithm
// is allocated.
//  Return Type: BOOL
//      TRUE(1)         PCR is allocated
//      FALSE(0)        PCR is not allocated
BOOL PcrIsAllocated(UINT32        pcr,     // IN: The number of the PCR
                    TPMI_ALG_HASH hashAlg  // IN: The PCR algorithm
);

//*** PcrDrtm()
// This function does the DRTM and H-CRTM processing it is called from
// _TPM_Hash_End.
void PcrDrtm(const TPMI_DH_PCR pcrHandle,  // IN: the index of the PCR to be
                                           //     modified
             const TPMI_ALG_HASH hash,     // IN: the bank identifier
             const TPM2B_DIGEST* digest    // IN: the digest to modify the PCR
);

//*** PCR_ClearAuth()
// This function is used to reset the PCR authorization values. It is called
// on TPM2_Startup(CLEAR) and TPM2_Clear().
void PCR_ClearAuth(void);

//*** PCRStartup()
// This function initializes the PCR subsystem at TPM2_Startup().
BOOL PCRStartup(STARTUP_TYPE type,     // IN: startup type
                BYTE         locality  // IN: startup locality
);

//*** PCRStateSave()
// This function is used to save the PCR values that will be restored on TPM Resume.
void PCRStateSave(TPM_SU type  // IN: startup type
);

//*** PCRIsStateSaved()
// This function indicates if the selected PCR is a PCR that is state saved
// on TPM2_Shutdown(STATE). The return value is based on PCR attributes.
//  Return Type: BOOL
//      TRUE(1)         PCR is state saved
//      FALSE(0)        PCR is not state saved
BOOL PCRIsStateSaved(TPMI_DH_PCR handle  // IN: PCR handle to be extended
);

//*** PCRIsResetAllowed()
// This function indicates if a PCR may be reset by the current command locality.
// The return value is based on PCR attributes, and not the PCR allocation.
//  Return Type: BOOL
//      TRUE(1)         TPM2_PCR_Reset is allowed
//      FALSE(0)        TPM2_PCR_Reset is not allowed
BOOL PCRIsResetAllowed(TPMI_DH_PCR handle  // IN: PCR handle to be extended
);

//*** PCRChanged()
// This function checks a PCR handle to see if the attributes for the PCR are set
// so that any change to the PCR causes an increment of the pcrCounter. If it does,
// then the function increments the counter. Will also bump the counter if the
// handle is zero which means that PCR 0 can not be in the TCB group. Bump on zero
// is used by TPM2_Clear().
void PCRChanged(TPM_HANDLE pcrHandle  // IN: the handle of the PCR that changed.
);

//*** PCRIsExtendAllowed()
// This function indicates a PCR may be extended at the current command locality.
// The return value is based on PCR attributes, and not the PCR allocation.
//  Return Type: BOOL
//      TRUE(1)         extend is allowed
//      FALSE(0)        extend is not allowed
BOOL PCRIsExtendAllowed(TPMI_DH_PCR handle  // IN: PCR handle to be extended
);

//*** PCRExtend()
// This function is used to extend a PCR in a specific bank.
void PCRExtend(TPMI_DH_PCR   handle,  // IN: PCR handle to be extended
               TPMI_ALG_HASH hash,    // IN: hash algorithm of PCR
               UINT32        size,    // IN: size of data to be extended
               BYTE*         data     // IN: data to be extended
);

//*** PCRComputeCurrentDigest()
// This function computes the digest of the selected PCR.
//
// As a side-effect, 'selection' is modified so that only the implemented PCR
// will have their bits still set.
TPM_RC PCRComputeCurrentDigest(
    TPMI_ALG_HASH       hashAlg,    // IN: hash algorithm to compute digest
    TPML_PCR_SELECTION* selection,  // IN/OUT: PCR selection (filtered on
                                    //     output)
    TPM2B_DIGEST* digest            // OUT: digest
);

//*** PCRRead()
// This function is used to read a list of selected PCR.  If the requested PCR
// number exceeds the maximum number that can be output, the 'selection' is
// adjusted to reflect the actual output PCR.
TPM_RC PCRRead(TPML_PCR_SELECTION* selection,  // IN/OUT: PCR selection (filtered on
                                               //     output)
               TPML_DIGEST* digest,            // OUT: digest
               UINT32*      pcrCounter  // OUT: the current value of PCR generation
                                        //     number
);

//*** PCRAllocate()
// This function is used to change the PCR allocation.
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        allocate failed
//      TPM_RC_PCR              improper allocation
TPM_RC
PCRAllocate(TPML_PCR_SELECTION* allocate,      // IN: required allocation
            UINT32*             maxPCR,        // OUT: Maximum number of PCR
            UINT32*             sizeNeeded,    // OUT: required space
            UINT32*             sizeAvailable  // OUT: available space
);

//*** PCRSetValue()
// This function is used to set the designated PCR in all banks to an initial value.
// The initial value is signed and will be sign extended into the entire PCR.
//
void PCRSetValue(TPM_HANDLE handle,       // IN: the handle of the PCR to set
                 INT8       initialValue  // IN: the value to set
);

//*** PCRResetDynamics
// This function is used to reset a dynamic PCR to 0.  This function is used in
// DRTM sequence.
void PCRResetDynamics(void);

//*** PCRCapGetAllocation()
// This function is used to get the current allocation of PCR banks.
//  Return Type: TPMI_YES_NO
//      YES         if the return count is 0
//      NO          if the return count is not 0
TPMI_YES_NO
PCRCapGetAllocation(UINT32              count,        // IN: count of return
                    TPML_PCR_SELECTION* pcrSelection  // OUT: PCR allocation list
);

//*** PCRCapGetProperties()
// This function returns a list of PCR properties starting at 'property'.
//  Return Type: TPMI_YES_NO
//      YES         if no more property is available
//      NO          if there are more properties not reported
TPMI_YES_NO
PCRCapGetProperties(TPM_PT_PCR property,  // IN: the starting PCR property
                    UINT32     count,     // IN: count of returned properties
                    TPML_TAGGED_PCR_PROPERTY* select  // OUT: PCR select
);

//*** PCRGetProperty()
// This function returns the selected PCR property.
//  Return Type: BOOL
//      TRUE(1)         the property type is implemented
//      FALSE(0)        the property type is not implemented
BOOL PCRGetProperty(TPM_PT_PCR property, TPMS_TAGGED_PCR_SELECT* select);

//*** PCRCapGetHandles()
// This function is used to get a list of handles of PCR, started from 'handle'.
// If 'handle' exceeds the maximum PCR handle range, an empty list will be
// returned and the return value will be NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PCRCapGetHandles(TPMI_DH_PCR  handle,     // IN: start handle
                 UINT32       count,      // IN: count of returned handles
                 TPML_HANDLE* handleList  // OUT: list of handle
);

//*** PCRCapGetOneHandle()
// This function is used to check whether a PCR handle exists.
BOOL PCRCapGetOneHandle(TPMI_DH_PCR handle  // IN: handle
);

#endif  // _PCR_FP_H_
