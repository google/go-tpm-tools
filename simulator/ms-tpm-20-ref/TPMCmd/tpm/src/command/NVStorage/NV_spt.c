//** Includes
#include "Tpm.h"
#include "NV_spt_fp.h"

//** Functions

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
)
{
    // If data is read locked, returns an error
    if(IS_ATTRIBUTE(attributes, TPMA_NV, READLOCKED))
        return TPM_RC_NV_LOCKED;
    // If the authorization was provided by the owner or platform, then check
    // that the attributes allow the read.  If the authorization handle
    // is the same as the index, then the checks were made when the authorization
    // was checked..
    if(authHandle == TPM_RH_OWNER)
    {
        // If Owner provided authorization then ONWERWRITE must be SET
        if(!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERREAD))
            return TPM_RC_NV_AUTHORIZATION;
    }
    else if(authHandle == TPM_RH_PLATFORM)
    {
        // If Platform provided authorization then PPWRITE must be SET
        if(!IS_ATTRIBUTE(attributes, TPMA_NV, PPREAD))
            return TPM_RC_NV_AUTHORIZATION;
    }
    // If neither Owner nor Platform provided authorization, make sure that it was
    // provided by this index.
    else if(authHandle != nvHandle)
        return TPM_RC_NV_AUTHORIZATION;

    // If the index has not been written, then the value cannot be read
    // NOTE: This has to come after other access checks to make sure that
    // the proper authorization is given to TPM2_NV_ReadLock()
    if(!IS_ATTRIBUTE(attributes, TPMA_NV, WRITTEN))
        return TPM_RC_NV_UNINITIALIZED;

    return TPM_RC_SUCCESS;
}

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
)
{
    // If data is write locked, returns an error
    if(IS_ATTRIBUTE(attributes, TPMA_NV, WRITELOCKED))
        return TPM_RC_NV_LOCKED;
    // If the authorization was provided by the owner or platform, then check
    // that the attributes allow the write.  If the authorization handle
    // is the same as the index, then the checks were made when the authorization
    // was checked..
    if(authHandle == TPM_RH_OWNER)
    {
        // If Owner provided authorization then ONWERWRITE must be SET
        if(!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERWRITE))
            return TPM_RC_NV_AUTHORIZATION;
    }
    else if(authHandle == TPM_RH_PLATFORM)
    {
        // If Platform provided authorization then PPWRITE must be SET
        if(!IS_ATTRIBUTE(attributes, TPMA_NV, PPWRITE))
            return TPM_RC_NV_AUTHORIZATION;
    }
    // If neither Owner nor Platform provided authorization, make sure that it was
    // provided by this index.
    else if(authHandle != nvHandle)
        return TPM_RC_NV_AUTHORIZATION;
    return TPM_RC_SUCCESS;
}

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
)
{

#if CC_ReadOnlyControl
    // When in Read-Only mode only allow the commands listed above on an
    // index with the ORDERLY and CLEAR_STCLEAR attributes set
    if(gc.readOnly
       && !(IS_ATTRIBUTE(attributes, TPMA_NV, ORDERLY)
            && IS_ATTRIBUTE(attributes, TPMA_NV, CLEAR_STCLEAR)))
        return TPM_RC_READ_ONLY;
#endif  // CC_ReadOnlyControl

    return TPM_RC_SUCCESS;
}

//*** NvClearOrderly()
// This function is used to cause gp.orderlyState to be cleared to the
// non-orderly state.
TPM_RC
NvClearOrderly(void)
{
    if(gp.orderlyState < SU_DA_USED_VALUE)
        RETURN_IF_NV_IS_NOT_AVAILABLE;
    g_clearOrderly = TRUE;
    return TPM_RC_SUCCESS;
}

//*** GetIndexAttributesByHandle()
// Function to return the TPMA_NV attributes of an index given a handle
// On success 'attributes' is set to receive the result
//   Return Type: BOOL
//      TRUE(1)   'index' is found
//      FALSE(0)  'index' is not found or not an NV index handle
static BOOL GetIndexAttributesByHandle(TPM_HANDLE index,      // IN:  index handle
                                       TPMA_NV*   attributes  // OUT: index attributes
)
{
    if(HandleGetType(index) == TPM_HT_NV_INDEX)
    {
        NV_INDEX* nvIndex = NvGetIndexInfo(index, NULL);
        if(nvIndex != NULL)
        {
            *attributes = nvIndex->publicArea.attributes;
            return TRUE;
        }
    }
    return FALSE;
}

//*** NvIsPinPassIndex()
// Function to check to see if an NV index is a PIN Pass Index
//  Return Type: BOOL
//      TRUE(1)         is pin pass
//      FALSE(0)        is not pin pass
BOOL NvIsPinPassIndex(TPM_HANDLE index  // IN: Handle to check
)
{
    TPMA_NV attributes;
    return GetIndexAttributesByHandle(index, &attributes)
           && IsNvPinPassIndex(attributes);
}

//*** NvIsPinCountedIndex()
// Function to check to see if an NV index is either a PIN Pass
// or a PIN FAIL Index
//  Return Type: BOOL
//      TRUE(1)         is pin pass or pin fail
//      FALSE(0)        is neither pin pass nor pin fail
BOOL NvIsPinCountedIndex(TPM_HANDLE index  // IN: Handle to check
)
{
    TPMA_NV attributes;
    return GetIndexAttributesByHandle(index, &attributes)
           && (IsNvPinPassIndex(attributes) || IsNvPinFailIndex(attributes));
}

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
)
{
    UINT16           dataSize, digestSize;
    BYTE             marshalBuffer[sizeof(TPMU_NV_PUBLIC_2)];
    BYTE*            buffer;
    INT32            bufferSize = sizeof(marshalBuffer);
    HASH_STATE       hashState;
    TPMT_NV_PUBLIC_2 public2;

    // Convert the legacy representation into the tagged-union representation.
    NvPublic2FromNvPublic(&nvIndex->publicArea, &public2);

    // Marshal the whole public area, but not the TPM_HT selector:
    // This is safe, because the TPM_HT is the first byte of the handle value,
    // which is already in every element of TPMT_NV_PUBLIC_2.
    // This allows the Name of an NV index calculated based on the
    // TPMT_NV_PUBLIC_2 to be consistent with the Name of the same index if it
    // has a TPMS_NV_PUBLIC representation.
    buffer = marshalBuffer;
    dataSize =
        TPMU_NV_PUBLIC_2_Marshal(&public2.nvPublic2,
                                 &buffer,
                                 &bufferSize,
                                 (UINT32)HandleGetType(nvIndex->publicArea.nvIndex));

    // hash public area
    digestSize = CryptHashStart(&hashState, nvIndex->publicArea.nameAlg);
    CryptDigestUpdate(&hashState, dataSize, marshalBuffer);

    // Complete digest leaving room for the nameAlg
    CryptHashEnd(&hashState, digestSize, &name->b.buffer[2]);

    // Include the nameAlg
    UINT16_TO_BYTE_ARRAY(nvIndex->publicArea.nameAlg, name->b.buffer);
    name->t.size = digestSize + 2;
    return name;
}

// NOTE: This is a lossy conversion: any expanded attributes are lost here.
// Calling code should return an error to the user, instead of dropping their
// data, if any of the expanded attributes are SET.
static TPMA_NV LegacyAttributesFromExpanded(TPMA_NV_EXP attributes)
{
    UINT64 attributes64;
    UINT32 attributes32;

    attributes64 = TPMA_NV_EXP_TO_UINT64(attributes);
    attributes32 = (UINT32)attributes64;

    return UINT32_TO_TPMA_NV(attributes32);
}

static TPMA_NV_EXP ExpandedAttributesFromLegacy(TPMA_NV attributes)
{
    UINT32 attributes32;
    UINT64 attributes64;

    attributes32 = TPMA_NV_TO_UINT32(attributes);
    attributes64 = (UINT64)attributes32;

    return UINT64_TO_TPMA_NV_EXP(attributes64);
}

//*** NvPublic2FromNvPublic()
// This function converts a legacy-form NV public (TPMS_NV_PUBLIC) into the
// generalized TPMT_NV_PUBLIC_2 tagged-union representation.
TPM_RC NvPublic2FromNvPublic(
    TPMS_NV_PUBLIC*   nvPublic,  // IN: the source S-form NV public area
    TPMT_NV_PUBLIC_2* nvPublic2  // OUT: the T-form NV public area to populate
)
{
    TPM_HT handleType = HandleGetType(nvPublic->nvIndex);

    switch(handleType)
    {
        case TPM_HT_NV_INDEX:
            nvPublic2->nvPublic2.nvIndex = *nvPublic;
            break;
        case TPM_HT_PERMANENT_NV:
            nvPublic2->nvPublic2.permanentNV = *nvPublic;
            break;
#if EXTERNAL_NV
        case TPM_HT_EXTERNAL_NV:
        {
            TPMS_NV_PUBLIC_EXP_ATTR* pub = &nvPublic2->nvPublic2.externalNV;

            pub->attributes = ExpandedAttributesFromLegacy(nvPublic->attributes);
            pub->authPolicy = nvPublic->authPolicy;
            pub->dataSize   = nvPublic->dataSize;
            pub->nameAlg    = nvPublic->nameAlg;
            pub->nvIndex    = nvPublic->nvIndex;
            break;
        }
#endif
        default:
            return TPM_RCS_HANDLE;
    }

    nvPublic2->handleType = handleType;
    return TPM_RC_SUCCESS;
}

//*** NvPublicFromNvPublic2()
// This function converts a tagged-union NV public (TPMT_NV_PUBLIC_2) into the
// legacy TPMS_NV_PUBLIC representation. This is a lossy conversion: any
// bits in the extended area of the attributes are lost, and the Name cannot be
// computed based on it.
TPM_RC NvPublicFromNvPublic2(
    TPMT_NV_PUBLIC_2* nvPublic2,  // IN: the source T-form NV public area
    TPMS_NV_PUBLIC*   nvPublic    // OUT: the S-form NV public area to populate
)
{
    switch(nvPublic2->handleType)
    {
        case TPM_HT_NV_INDEX:
            *nvPublic = nvPublic2->nvPublic2.nvIndex;
            break;
        case TPM_HT_PERMANENT_NV:
            *nvPublic = nvPublic2->nvPublic2.permanentNV;
            break;
#if EXTERNAL_NV
        case TPM_HT_EXTERNAL_NV:
        {
            TPMS_NV_PUBLIC_EXP_ATTR* pub = &nvPublic2->nvPublic2.externalNV;

            nvPublic->attributes = LegacyAttributesFromExpanded(pub->attributes);
            nvPublic->authPolicy = pub->authPolicy;
            nvPublic->dataSize   = pub->dataSize;
            nvPublic->nameAlg    = pub->nameAlg;
            break;
        }
#endif
        default:
            return TPM_RCS_HANDLE;
    }

    return TPM_RC_SUCCESS;
}

//*** NvDefineSpace()
// This function combines the common functionality of TPM2_NV_DefineSpace and
// TPM2_NV_DefineSpace2.
TPM_RC NvDefineSpace(TPMI_RH_PROVISION authHandle,
                     TPM2B_AUTH*       auth,
                     TPMS_NV_PUBLIC*   publicInfo,
                     TPM_RC            blameAuthHandle,
                     TPM_RC            blameAuth,
                     TPM_RC            blamePublic)
{
    TPMA_NV attributes = publicInfo->attributes;
    UINT16  nameSize;

    nameSize = CryptHashGetDigestSize(publicInfo->nameAlg);

    // Input Validation

    // Checks not specific to type

    // If the UndefineSpaceSpecial command is not implemented, then can't have
    // an index that can only be deleted with policy
#if CC_NV_UndefineSpaceSpecial == NO
    if(IS_ATTRIBUTE(attributes, TPMA_NV, POLICY_DELETE))
        return TPM_RCS_ATTRIBUTES + blamePublic;
#endif

    // check that the authPolicy consistent with hash algorithm

    if(publicInfo->authPolicy.t.size != 0
       && publicInfo->authPolicy.t.size != nameSize)
        return TPM_RCS_SIZE + blamePublic;

    // make sure that the authValue is not too large
    if(MemoryRemoveTrailingZeros(auth) > CryptHashGetDigestSize(publicInfo->nameAlg))
        return TPM_RCS_SIZE + blameAuth;

    // If an index is being created by the owner and shEnable is
    // clear, then we would not reach this point because ownerAuth
    // can't be given when shEnable is CLEAR. However, if phEnable
    // is SET but phEnableNV is CLEAR, we have to check here
    if(authHandle == TPM_RH_PLATFORM && gc.phEnableNV == CLEAR)
        return TPM_RCS_HIERARCHY + blameAuthHandle;

    // Attribute checks
    // Eliminate the unsupported types
    switch(GET_TPM_NT(attributes))
    {
#if CC_NV_Increment == YES
        case TPM_NT_COUNTER:
#endif
#if CC_NV_SetBits == YES
        case TPM_NT_BITS:
#endif
#if CC_NV_Extend == YES
        case TPM_NT_EXTEND:
#endif
#if CC_PolicySecret == YES && defined TPM_NT_PIN_PASS
        case TPM_NT_PIN_PASS:
        case TPM_NT_PIN_FAIL:
#endif
        case TPM_NT_ORDINARY:
            break;
        default:
            return TPM_RCS_ATTRIBUTES + blamePublic;
            break;
    }
    // Check that the sizes are OK based on the type
    switch(GET_TPM_NT(attributes))
    {
        case TPM_NT_ORDINARY:
            // Can't exceed the allowed size for the implementation
            if(publicInfo->dataSize > MAX_NV_INDEX_SIZE)
                return TPM_RCS_SIZE + blamePublic;
            break;
        case TPM_NT_EXTEND:
            if(publicInfo->dataSize != nameSize)
                return TPM_RCS_SIZE + blamePublic;
            break;
        default:
            // Everything else needs a size of 8
            if(publicInfo->dataSize != 8)
                return TPM_RCS_SIZE + blamePublic;
            break;
    }
    // Handle other specifics
    switch(GET_TPM_NT(attributes))
    {
        case TPM_NT_COUNTER:
            // Counter can't have TPMA_NV_CLEAR_STCLEAR SET (don't clear counters)
            if(IS_ATTRIBUTE(attributes, TPMA_NV, CLEAR_STCLEAR))
                return TPM_RCS_ATTRIBUTES + blamePublic;
            break;
#ifdef TPM_NT_PIN_FAIL
        case TPM_NT_PIN_FAIL:
            // NV_NO_DA must be SET and AUTHWRITE must be CLEAR
            // NOTE: As with a PIN_PASS index, the authValue of the index is not
            // available until the index is written. If AUTHWRITE is the only way to
            // write then index, it could never be written. Rather than go through
            // all of the other possible ways to write the Index, it is simply
            // prohibited to write the index with the authValue. Other checks
            // below will insure that there seems to be a way to write the index
            // (i.e., with platform authorization , owner authorization,
            // or with policyAuth.)
            // It is not allowed to create a PIN Index that can't be modified.
            if(!IS_ATTRIBUTE(attributes, TPMA_NV, NO_DA))
                return TPM_RCS_ATTRIBUTES + blamePublic;
#endif
#ifdef TPM_NT_PIN_PASS
        case TPM_NT_PIN_PASS:
            // AUTHWRITE must be CLEAR (see note above to TPM_NT_PIN_FAIL)
            if(IS_ATTRIBUTE(attributes, TPMA_NV, AUTHWRITE)
               || IS_ATTRIBUTE(attributes, TPMA_NV, GLOBALLOCK)
               || IS_ATTRIBUTE(attributes, TPMA_NV, WRITEDEFINE))
                return TPM_RCS_ATTRIBUTES + blamePublic;
#endif  // this comes before break because PIN_FAIL falls through
            break;
        default:
            break;
    }

    // Locks may not be SET and written cannot be SET
    if(IS_ATTRIBUTE(attributes, TPMA_NV, WRITTEN)
       || IS_ATTRIBUTE(attributes, TPMA_NV, WRITELOCKED)
       || IS_ATTRIBUTE(attributes, TPMA_NV, READLOCKED))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // There must be a way to read the index.
    if(!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, PPREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, AUTHREAD)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, POLICYREAD))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // There must be a way to write the index
    if(!IS_ATTRIBUTE(attributes, TPMA_NV, OWNERWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, PPWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, AUTHWRITE)
       && !IS_ATTRIBUTE(attributes, TPMA_NV, POLICYWRITE))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // An index with TPMA_NV_CLEAR_STCLEAR can't have TPMA_NV_WRITEDEFINE SET
    if(IS_ATTRIBUTE(attributes, TPMA_NV, CLEAR_STCLEAR)
       && IS_ATTRIBUTE(attributes, TPMA_NV, WRITEDEFINE))
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // Make sure that the creator of the index can delete the index
    if((IS_ATTRIBUTE(attributes, TPMA_NV, PLATFORMCREATE)
        && authHandle == TPM_RH_OWNER)
       || (!IS_ATTRIBUTE(attributes, TPMA_NV, PLATFORMCREATE)
           && authHandle == TPM_RH_PLATFORM))
        return TPM_RCS_ATTRIBUTES + blameAuthHandle;

    // If TPMA_NV_POLICY_DELETE is SET, then the index must be defined by
    // the platform
    if(IS_ATTRIBUTE(attributes, TPMA_NV, POLICY_DELETE)
       && TPM_RH_PLATFORM != authHandle)
        return TPM_RCS_ATTRIBUTES + blamePublic;

    // Make sure that the TPMA_NV_WRITEALL is not set if the index size is larger
    // than the allowed NV buffer size.
    if(publicInfo->dataSize > MAX_NV_BUFFER_SIZE
       && IS_ATTRIBUTE(attributes, TPMA_NV, WRITEALL))
        return TPM_RCS_SIZE + blamePublic;

    // And finally, see if the index is already defined.
    if(NvIndexIsDefined(publicInfo->nvIndex))
        return TPM_RC_NV_DEFINED;

    // Internal Data Update
    // define the space.  A TPM_RC_NV_SPACE error may be returned at this point
    return NvDefineIndex(publicInfo, auth);
}