//** Description
// This file contains the functions that return the type of a handle.

//** Includes
#include "Tpm.h"

//** Functions

//*** HandleGetType()
// This function returns the type of a handle which is the MSO of the handle.
TPM_HT
HandleGetType(TPM_HANDLE handle  // IN: a handle to be checked
)
{
    // return the upper bytes of input data
    return (TPM_HT)((handle & HR_RANGE_MASK) >> HR_SHIFT);
}

//*** NextPermanentHandle()
// This function returns the permanent handle that is equal to the input value or
// is the next higher value. If there is no handle with the input value and there
// is no next higher value, it returns 0:
TPM_HANDLE
NextPermanentHandle(TPM_HANDLE inHandle  // IN: the handle to check
)
{
    // If inHandle is below the start of the range of permanent handles
    // set it to the start and scan from there
    if(inHandle < TPM_RH_FIRST)
        inHandle = TPM_RH_FIRST;
    // scan from input value until we find an implemented permanent handle
    // or go out of range
    for(; inHandle <= TPM_RH_LAST; inHandle++)
    {
        // Skip over gaps in the reserved handle space.
        if(inHandle > TPM_RH_FW_NULL && inHandle < SVN_OWNER_FIRST)
            inHandle = SVN_OWNER_FIRST;
        if(inHandle > SVN_OWNER_FIRST && inHandle <= SVN_OWNER_LAST)
            inHandle = SVN_ENDORSEMENT_FIRST;
        if(inHandle > SVN_ENDORSEMENT_FIRST && inHandle <= SVN_ENDORSEMENT_LAST)
            inHandle = SVN_PLATFORM_FIRST;
        if(inHandle > SVN_PLATFORM_FIRST && inHandle <= SVN_PLATFORM_LAST)
            inHandle = SVN_NULL_FIRST;
        if(inHandle > SVN_NULL_FIRST)
            inHandle = TPM_RH_LAST;

        switch(inHandle)
        {
            case TPM_RH_OWNER:
            case TPM_RH_NULL:
            case TPM_RS_PW:
            case TPM_RH_LOCKOUT:
            case TPM_RH_ENDORSEMENT:
            case TPM_RH_PLATFORM:
            case TPM_RH_PLATFORM_NV:
#if FW_LIMITED_SUPPORT
            case TPM_RH_FW_OWNER:
            case TPM_RH_FW_ENDORSEMENT:
            case TPM_RH_FW_PLATFORM:
            case TPM_RH_FW_NULL:
#endif
#if SVN_LIMITED_SUPPORT
            case TPM_RH_SVN_OWNER_BASE:
            case TPM_RH_SVN_ENDORSEMENT_BASE:
            case TPM_RH_SVN_PLATFORM_BASE:
            case TPM_RH_SVN_NULL_BASE:
#endif
#if VENDOR_PERMANENT_AUTH_ENABLED == YES
            case VENDOR_PERMANENT_AUTH_HANDLE:
#endif
// Each of the implemented ACT
#define ACT_IMPLEMENTED_CASE(N) case TPM_RH_ACT_##N:

                FOR_EACH_ACT(ACT_IMPLEMENTED_CASE)

                return inHandle;
                break;
            default:
                break;
        }
    }
    // Out of range on the top
    return 0;
}

//*** PermanentCapGetHandles()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentCapGetHandles(TPM_HANDLE   handle,     // IN: start handle
                       UINT32       count,      // IN: count of returned handles
                       TPML_HANDLE* handleList  // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;
    UINT32      i;

    VERIFY(HandleGetType(handle) == TPM_HT_PERMANENT, FATAL_ERROR_ASSERT, NO);

    // Initialize output handle list
    handleList->count = 0;

    // The maximum count of handles we may return is MAX_CAP_HANDLES
    if(count > MAX_CAP_HANDLES)
        count = MAX_CAP_HANDLES;

    // Iterate permanent handle range
    for(i = NextPermanentHandle(handle); i != 0; i = NextPermanentHandle(i + 1))
    {
        if(handleList->count < count)
        {
            // If we have not filled up the return list, add this permanent
            // handle to it
            handleList->handle[handleList->count] = i;
            handleList->count++;
        }
        else
        {
            // If the return list is full but we still have permanent handle
            // available, report this and stop iterating
            more = YES;
            break;
        }
    }
    return more;
}

//*** PermanentCapGetOneHandle()
// This function returns whether a permanent handle exists.
BOOL PermanentCapGetOneHandle(TPM_HANDLE handle)  // IN: handle
{
    UINT32 i;

    pAssert_BOOL(HandleGetType(handle) == TPM_HT_PERMANENT);

    // Iterate permanent handle range
    for(i = NextPermanentHandle(handle); i != 0; i = NextPermanentHandle(i + 1))
    {
        if(i == handle)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//*** PermanentHandleGetPolicy()
// This function returns a list of the permanent handles of PCR, started from
// 'handle'. If 'handle' is larger than the largest permanent handle, an empty list
// will be returned with 'more' set to NO.
//  Return Type: TPMI_YES_NO
//      YES         if there are more handles available
//      NO          all the available handles has been returned
TPMI_YES_NO
PermanentHandleGetPolicy(TPM_HANDLE handle,  // IN: start handle
                         UINT32     count,   // IN: max count of returned handles
                         TPML_TAGGED_POLICY* policyList  // OUT: list of handle
)
{
    TPMI_YES_NO more = NO;

    VERIFY(HandleGetType(handle) == TPM_HT_PERMANENT, FATAL_ERROR_ASSERT, NO);

    // Initialize output handle list
    policyList->count = 0;

    // The maximum count of policies we may return is MAX_TAGGED_POLICIES
    if(count > MAX_TAGGED_POLICIES)
        count = MAX_TAGGED_POLICIES;

    // Iterate permanent handle range
    for(handle = NextPermanentHandle(handle); handle != 0;
        handle = NextPermanentHandle(handle + 1))
    {
        TPM2B_DIGEST policyDigest;
        TPM_ALG_ID   policyAlg;
        // Check to see if this permanent handle has a policy
        policyAlg = EntityGetAuthPolicy(handle, &policyDigest);
        if(policyAlg == TPM_ALG_ERROR)
            continue;
        if(policyList->count < count)
        {
            // If we have not filled up the return list, add this
            // policy to the list;
            policyList->policies[policyList->count].handle             = handle;
            policyList->policies[policyList->count].policyHash.hashAlg = policyAlg;
            MemoryCopy(&policyList->policies[policyList->count].policyHash.digest,
                       policyDigest.t.buffer,
                       policyDigest.t.size);
            policyList->count++;
        }
        else
        {
            // If the return list is full but we still have permanent handle
            // available, report this and stop iterating
            more = YES;
            break;
        }
    }
    return more;
}

//*** PermanentHandleGetOnePolicy()
// This function returns a permanent handle's policy, if present.
BOOL PermanentHandleGetOnePolicy(TPM_HANDLE          handle,  // IN: handle
                                 TPMS_TAGGED_POLICY* policy   // OUT: tagged policy
)
{
    pAssert_BOOL(HandleGetType(handle) == TPM_HT_PERMANENT);

    if(NextPermanentHandle(handle) == handle)
    {
        TPM2B_DIGEST policyDigest;
        TPM_ALG_ID   policyAlg;
        // Check to see if this permanent handle has a policy
        policyAlg = EntityGetAuthPolicy(handle, &policyDigest);
        if(policyAlg == TPM_ALG_ERROR)
        {
            return FALSE;
        }
        policy->handle             = handle;
        policy->policyHash.hashAlg = policyAlg;
        MemoryCopy(
            &policy->policyHash.digest, policyDigest.t.buffer, policyDigest.t.size);
        return TRUE;
    }
    return FALSE;
}
