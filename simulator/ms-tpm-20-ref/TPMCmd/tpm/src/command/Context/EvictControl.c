#include "Tpm.h"
#include "EvictControl_fp.h"

#if CC_EvictControl  // Conditional expansion of this file

/*(See part 3 specification)
// Make a transient object persistent or evict a persistent object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES   an object with 'temporary', 'stClear' or 'publicOnly'
//                          attribute SET cannot be made persistent
//      TPM_RC_HIERARCHY    'auth' cannot authorize the operation in the hierarchy
//                          of 'evictObject';
//                          an object in a firmware-bound or SVN-bound hierarchy
//                          cannot be made persistent.
//      TPM_RC_HANDLE       'evictHandle' of the persistent object to be evicted is
//                          not the same as the 'persistentHandle' argument
//      TPM_RC_NV_HANDLE    'persistentHandle' is unavailable
//      TPM_RC_NV_SPACE     no space in NV to make 'evictHandle' persistent
//      TPM_RC_RANGE        'persistentHandle' is not in the range corresponding to
//                          the hierarchy of 'evictObject'
TPM_RC
TPM2_EvictControl(EvictControl_In* in  // IN: input parameter list
)
{
    TPM_RC  result;
    OBJECT* evictObject;

    // Input Validation

    // Get internal object pointer
    evictObject = HandleToObject(in->objectHandle);
    pAssert_RC(evictObject != NULL);

    // Objects in a firmware-limited or SVN-limited hierarchy cannot be made
    // persistent.
    if(HierarchyIsFirmwareLimited(evictObject->hierarchy)
       || HierarchyIsSvnLimited(evictObject->hierarchy))
        return TPM_RCS_HIERARCHY + RC_EvictControl_objectHandle;

    // Temporary, stClear or public only objects can not be made persistent
    if(evictObject->attributes.temporary == SET
       || evictObject->attributes.stClear == SET
       || evictObject->attributes.publicOnly == SET)
        return TPM_RCS_ATTRIBUTES + RC_EvictControl_objectHandle;

    // If objectHandle refers to a persistent object, it should be the same as
    // input persistentHandle
    if(evictObject->attributes.evict == SET
       && evictObject->evictHandle != in->persistentHandle)
        return TPM_RCS_HANDLE + RC_EvictControl_objectHandle;

    // Additional authorization validation
    if(in->auth == TPM_RH_PLATFORM)
    {
        // To make persistent
        if(evictObject->attributes.evict == CLEAR)
        {
            // PlatformAuth can not set evict object in storage or endorsement
            // hierarchy
            if(evictObject->attributes.ppsHierarchy == CLEAR)
                return TPM_RCS_HIERARCHY + RC_EvictControl_objectHandle;
            // Platform cannot use a handle outside of platform persistent range.
            if(!NvIsPlatformPersistentHandle(in->persistentHandle))
                return TPM_RCS_RANGE + RC_EvictControl_persistentHandle;
        }
        // PlatformAuth can delete any persistent object
    }
    else if(in->auth == TPM_RH_OWNER)
    {
        // OwnerAuth can not set or clear evict object in platform hierarchy
        if(evictObject->attributes.ppsHierarchy == SET)
            return TPM_RCS_HIERARCHY + RC_EvictControl_objectHandle;

        // Owner cannot use a handle outside of owner persistent range.
        if(evictObject->attributes.evict == CLEAR
           && !NvIsOwnerPersistentHandle(in->persistentHandle))
            return TPM_RCS_RANGE + RC_EvictControl_persistentHandle;
    }
    else
    {
        // Other authorization is not allowed in this command and should have been
        // filtered out in unmarshal process
        FAIL(FATAL_ERROR_INTERNAL);
    }
    // Internal Data Update
    // Change evict state
    if(evictObject->attributes.evict == CLEAR)
    {
        // Make object persistent
        if(NvFindHandle(in->persistentHandle) != 0)
            return TPM_RC_NV_DEFINED;
        // A TPM_RC_NV_HANDLE or TPM_RC_NV_SPACE error may be returned at this
        // point
        result = NvAddEvictObject(in->persistentHandle, evictObject);
    }
    else
    {
        // Delete the persistent object in NV
        result = NvDeleteEvict(evictObject->evictHandle);
    }
    return result;
}

#endif  // CC_EvictControl