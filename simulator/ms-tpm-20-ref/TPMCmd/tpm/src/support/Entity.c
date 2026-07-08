//** Description
// The functions in this file are used for accessing properties for handles of
// various types. Functions in other files require handles of a specific
// type but the functions in this file allow use of any handle type.

//** Includes

#include "Tpm.h"
#include <platform_interface/prototypes/platform_virtual_nv_fp.h>

//** Functions
//*** EntityGetLoadStatus()
// This function will check that all the handles access loaded entities.
//  Return Type: TPM_RC
//      TPM_RC_HANDLE           handle type does not match
//      TPM_RC_REFERENCE_Hx     entity is not present
//      TPM_RC_HIERARCHY        entity belongs to a disabled hierarchy
//      TPM_RC_OBJECT_MEMORY    handle is an evict object but there is no
//                               space to load it to RAM
TPM_RC
EntityGetLoadStatus(COMMAND* command  // IN/OUT: command parsing structure
)
{
    UINT32 i;
    TPM_RC result = TPM_RC_SUCCESS;
    //
    for(i = 0; i < command->handleNum; i++)
    {
        TPM_HANDLE handle = command->handles[i];
        switch(HandleGetType(handle))
        {
            // For handles associated with hierarchies, the entity is present
            // only if the associated enable is SET.
            case TPM_HT_PERMANENT:
                switch(handle)
                {
                    // First handle non-hierarchy cases
#if VENDOR_PERMANENT_AUTH_ENABLED == YES
                    case VENDOR_PERMANENT_AUTH_HANDLE:
                        if(!gc.ehEnable)
                            result = TPM_RC_HIERARCHY;
                        break;
#endif
                        // PW session handle and lockout handle are always available
                    case TPM_RS_PW:
                        // Need to be careful for lockout. Lockout is always available
                        // for policy checks but not always available when authValue
                        // is being checked.
                    case TPM_RH_LOCKOUT:
                        // Rather than have #ifdefs all over the code,
                        // CASE_ACT_HANDLE is defined in ACT.h. It is 'case TPM_RH_ACT_x:'
                        // FOR_EACH_ACT(CASE_ACT_HANDLE) creates a simple
                        // case TPM_RH_ACT_x: // for each of the implemented ACT.
                        FOR_EACH_ACT(CASE_ACT_HANDLE)
                        break;
                    default:
                        // If the implementation has a manufacturer-specific value
                        // then test for it here. Since this implementation does
                        // not have any, this implementation returns the same failure
                        // that unmarshaling of a bad handle would produce.
                        if(((TPM_RH)handle >= TPM_RH_AUTH_00)
                           && ((TPM_RH)handle <= TPM_RH_AUTH_FF))
                            // if the implementation has a manufacturer-specific value
                            result = TPM_RC_VALUE;
                        else
                            // The handle either refers to a hierarchy or is invalid.
                            result = ValidateHierarchy(handle);
                        break;
                }
                break;
            case TPM_HT_TRANSIENT:
                // For a transient object, check if the handle is associated
                // with a loaded object.
                if(!IsObjectPresent(handle))
                    result = TPM_RC_REFERENCE_H0;
                break;
            case TPM_HT_PERSISTENT:
                // Persistent object
                // Copy the persistent object to RAM and replace the handle with the
                // handle of the assigned slot.  A TPM_RC_OBJECT_MEMORY,
                // TPM_RC_HIERARCHY or TPM_RC_REFERENCE_H0 error may be returned by
                // ObjectLoadEvict()
                result = ObjectLoadEvict(&command->handles[i], command->index);
                break;
            case TPM_HT_HMAC_SESSION:
                // For an HMAC session, see if the session is loaded
                // and if the session in the session slot is actually
                // an HMAC session.
                if(SessionIsLoaded(handle))
                {
                    SESSION* session;
                    session = SessionGet(handle);
                    pAssert_RC(session != NULL);
                    // Check if the session is a HMAC session
                    if(session->attributes.isPolicy == SET)
                        result = TPM_RC_HANDLE;
                }
                else
                    result = TPM_RC_REFERENCE_H0;
                break;
            case TPM_HT_POLICY_SESSION:
                // For a policy session, see if the session is loaded
                // and if the session in the session slot is actually
                // a policy session.
                if(SessionIsLoaded(handle))
                {
                    SESSION* session;
                    session = SessionGet(handle);
                    pAssert_RC(session != NULL);
                    // Check if the session is a policy session
                    if(session->attributes.isPolicy == CLEAR)
                        result = TPM_RC_HANDLE;
                }
                else
                    result = TPM_RC_REFERENCE_H0;
                break;
            case TPM_HT_NV_INDEX:
            {
                // For an NV Index, use the platform-specific routine
                // to search the IN Index space.
                BOOL commandAcceptsVirtualHandles =
                    _plat__NvOperationAcceptsVirtualHandles(command->index);
                result = NvIndexIsAccessible(handle, commandAcceptsVirtualHandles);
                break;
            }
            case TPM_HT_PCR:
                // Any PCR handle that is unmarshaled successfully referenced
                // a PCR that is defined.
                break;
#if CC_AC_Send
            case TPM_HT_AC:
                // Use the TPM-specific routine to search for the AC
                result = AcIsAccessible(handle);
                break;
#endif
            case TPM_HT_EXTERNAL_NV:
            case TPM_HT_PERMANENT_NV:
                // Not yet supported.
                result = TPM_RC_VALUE;
                break;
            default:
                // Any other handle type is a defect in the unmarshaling code.
                FAIL(FATAL_ERROR_INTERNAL);
                break;
        }
        if(result != TPM_RC_SUCCESS)
        {
            if(result == TPM_RC_REFERENCE_H0)
                result = result + i;
            else
                result = RcSafeAddToResult(result, TPM_RC_H + g_rcIndex[i]);
            break;
        }
    }
    return result;
}

//*** EntityGetAuthValue()
// This function is used to access the 'authValue' associated with a handle.
// This function assumes that the handle references an entity that is accessible
// and the handle is not for a persistent objects. That is EntityGetLoadStatus()
// should have been called. Also, the accessibility of the authValue should have
// been verified by IsAuthValueAvailable().
//
// This function copies the authorization value of the entity to 'auth'.
// Return Type: UINT16
//      count           number of bytes in the authValue with 0's stripped
UINT16
EntityGetAuthValue(TPMI_DH_ENTITY handle,  // IN: handle of entity
                   TPM2B_AUTH*    auth     // OUT: authValue of the entity
)
{
    TPM2B_AUTH* pAuth     = NULL;
    NV_INDEX*   nvIndex   = NULL;
    NV_INDEX    tempIndex = {0};

    auth->t.size          = 0;

    switch(HandleGetType(handle))
    {
        case TPM_HT_PERMANENT:
        {
            switch(HierarchyNormalizeHandle(handle))
            {
                case TPM_RH_OWNER:
                    // ownerAuth for TPM_RH_OWNER
                    pAuth = &gp.ownerAuth;
                    break;
                case TPM_RH_ENDORSEMENT:
                    // endorsementAuth for TPM_RH_ENDORSEMENT
                    pAuth = &gp.endorsementAuth;
                    break;

                    // The ACT use platformAuth for auth
                    FOR_EACH_ACT(CASE_ACT_HANDLE)

                case TPM_RH_PLATFORM:
                    // platformAuth for TPM_RH_PLATFORM
                    pAuth = &gc.platformAuth;
                    break;
                case TPM_RH_LOCKOUT:
                    // lockoutAuth for TPM_RH_LOCKOUT
                    pAuth = &gp.lockoutAuth;
                    break;
                case TPM_RH_NULL:
                    // nullAuth for TPM_RH_NULL. Return 0 directly here
                    return 0;
                    break;
#if VENDOR_PERMANENT_AUTH_ENABLED == YES
                case VENDOR_PERMANENT_AUTH_HANDLE:
                    // vendor authorization value
                    pAuth = &g_platformUniqueAuth;
#endif
                default:
                    // If any other permanent handle is present it is
                    // a code defect.
                    FAIL(FATAL_ERROR_INTERNAL);
                    break;
            }
            break;
        }
        case TPM_HT_TRANSIENT:
            // authValue for an object
            // A persistent object would have been copied into RAM
            // and would have an transient object handle here.
            {
                OBJECT* object;

                object = HandleToObject(handle);
                // special handling if this is a sequence object
                if(ObjectIsSequence(object))
                {
                    pAuth = &((HASH_OBJECT*)object)->auth;
                }
                else
                {
                    // Authorization is available only when the private portion of
                    // the object is loaded.  The check should be made before
                    // this function is called
                    pAssert_ZERO(object && object->attributes.publicOnly == CLEAR);
                    pAuth = &object->sensitive.authValue;
                }
            }
            break;
        case TPM_HT_NV_INDEX:
            // authValue for an NV index
            {
                if(_plat__IsNvVirtualIndex(handle))
                {
                    _plat__NvVirtual_PopulateNvIndexInfo(
                        handle, &tempIndex.publicArea, &tempIndex.authValue);
                    nvIndex = &tempIndex;
                }
                else
                {
                    nvIndex = NvGetIndexInfo(handle, NULL);
                }
                pAssert_ZERO(nvIndex != NULL);

                pAuth = &nvIndex->authValue;
            }
            break;
        case TPM_HT_PCR:
            // authValue for PCR
            pAuth = PCRGetAuthValue(handle);
            break;
        default:
            // If any other handle type is present here, then there is a defect
            // in the unmarshaling code.
            FAIL(FATAL_ERROR_INTERNAL);
            break;
    }
    // Copy the authValue
    MemoryCopy2B((TPM2B*)auth, (TPM2B*)pAuth, sizeof(auth->t.buffer));
    MemoryRemoveTrailingZeros(auth);
    return auth->t.size;
}

//*** EntityGetAuthPolicy()
// This function is used to access the 'authPolicy' associated with a handle.
// This function assumes that the handle references an entity that is accessible
// and the handle is not for a persistent objects. That is EntityGetLoadStatus()
// should have been called. Also, the accessibility of the authPolicy should have
// been verified by IsAuthPolicyAvailable().
//
// This function copies the authorization policy of the entity to 'authPolicy'.
//
//  The return value is the hash algorithm for the policy.
TPMI_ALG_HASH
EntityGetAuthPolicy(TPMI_DH_ENTITY handle,     // IN: handle of entity
                    TPM2B_DIGEST*  authPolicy  // OUT: authPolicy of the entity
)
{
    TPMI_ALG_HASH hashAlg = TPM_ALG_NULL;
    authPolicy->t.size    = 0;

    switch(HandleGetType(handle))
    {
        case TPM_HT_PERMANENT:
            switch(HierarchyNormalizeHandle(handle))
            {
                case TPM_RH_OWNER:
                    // ownerPolicy for TPM_RH_OWNER
                    *authPolicy = gp.ownerPolicy;
                    hashAlg     = gp.ownerAlg;
                    break;
                case TPM_RH_ENDORSEMENT:
                    // endorsementPolicy for TPM_RH_ENDORSEMENT
                    *authPolicy = gp.endorsementPolicy;
                    hashAlg     = gp.endorsementAlg;
                    break;
                case TPM_RH_PLATFORM:
                    // platformPolicy for TPM_RH_PLATFORM
                    *authPolicy = gc.platformPolicy;
                    hashAlg     = gc.platformAlg;
                    break;
                case TPM_RH_LOCKOUT:
                    // lockoutPolicy for TPM_RH_LOCKOUT
                    *authPolicy = gp.lockoutPolicy;
                    hashAlg     = gp.lockoutAlg;
                    break;
#define ACT_GET_POLICY(N)                    \
    case TPM_RH_ACT_##N:                     \
        *authPolicy = go.ACT_##N.authPolicy; \
        hashAlg     = go.ACT_##N.hashAlg;    \
        break;
                    // Get the policy for each implemented ACT
                    FOR_EACH_ACT(ACT_GET_POLICY)
                default:
                    hashAlg = TPM_ALG_ERROR;
                    break;
            }
            break;
        case TPM_HT_TRANSIENT:
            // authPolicy for an object
            {
                OBJECT* object = HandleToObject(handle);
                GOTO_ERROR_UNLESS(object != NULL);
                *authPolicy = object->publicArea.authPolicy;
                hashAlg     = object->publicArea.nameAlg;
            }
            break;
        case TPM_HT_NV_INDEX:
            // authPolicy for a NV index
            {
                NV_INDEX* nvIndex   = NvGetIndexInfo(handle, NULL);
                NV_INDEX  tempNvIndex = {0};
                if(nvIndex == NULL)
                {
                    if(!_plat__IsNvVirtualIndex(handle))
                    {
                        FAIL_IMMEDIATE(FATAL_ERROR_INTERNAL, TPM_ALG_NULL);
                    }
                    else
                    {
                        _plat__NvVirtual_PopulateNvIndexInfo(
                            handle, &tempNvIndex.publicArea, &tempNvIndex.authValue);
                        nvIndex = &tempNvIndex;
                    }
                }
                // nvIndex guaranteed non-null at this point.

                *authPolicy = nvIndex->publicArea.authPolicy;
                hashAlg     = nvIndex->publicArea.nameAlg;
            }
            break;
        case TPM_HT_PCR:
            // authPolicy for a PCR
            hashAlg = PCRGetAuthPolicy(handle, authPolicy);
            break;
        default:
            // If any other handle type is present it is a code defect.
            FAIL(FATAL_ERROR_INTERNAL);
            break;
    }
Error:
    return hashAlg;
}

//*** EntityGetName()
// This function returns the Name associated with a handle.
TPM2B_NAME* EntityGetName(TPMI_DH_ENTITY handle,  // IN: handle of entity
                          TPM2B_NAME*    name     // OUT: name of entity
)
{
    switch(HandleGetType(handle))
    {
        case TPM_HT_TRANSIENT:
        {
            // Name for an object
            OBJECT* object = HandleToObject(handle);

            if(object == NULL)
            {
                // should not have gotten in this function in this case but we
                // can safely enter failure mode and return an empty name
                // through the if statement below.
                FAIL_NORET(FATAL_ERROR_ASSERT);
            }

            // an invalid object or an object with no nameAlg has no name
            if(object == NULL || object->publicArea.nameAlg == TPM_ALG_NULL)
                name->b.size = 0;
            else
                *name = object->name;
            break;
        }
        case TPM_HT_NV_INDEX:
            // Name for a NV index
            NvGetNameByIndexHandle(handle, name);
            break;
        default:
            // For all other types, the handle is the Name
            name->t.size = sizeof(TPM_HANDLE);
            UINT32_TO_BYTE_ARRAY(handle, name->t.name);
            break;
    }
    return name;
}

//*** EntityGetHierarchy()
// This function returns the hierarchy handle associated with an entity.
// a) A handle that is a hierarchy handle is associated with itself.
// b) An NV index belongs to TPM_RH_PLATFORM if TPMA_NV_PLATFORMCREATE,
//    is SET, otherwise it belongs to TPM_RH_OWNER
// c) An object handle belongs to its hierarchy.
TPMI_RH_HIERARCHY
EntityGetHierarchy(TPMI_DH_ENTITY handle  // IN :handle of entity
)
{
    TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;

    switch(HandleGetType(handle))
    {
        case TPM_HT_PERMANENT:
            // hierarchy for a permanent handle

            if(HierarchyIsFirmwareLimited(handle) || HierarchyIsSvnLimited(handle))
            {
                hierarchy = handle;
                break;
            }

            switch(handle)
            {
                case TPM_RH_PLATFORM:
                case TPM_RH_ENDORSEMENT:
                case TPM_RH_NULL:
                    hierarchy = handle;
                    break;
                // all other permanent handles are associated with the owner
                // hierarchy. (should only be TPM_RH_OWNER and TPM_RH_LOCKOUT)
                default:
                    hierarchy = TPM_RH_OWNER;
                    break;
            }
            break;
        case TPM_HT_NV_INDEX:
            // hierarchy for NV index
            {
                NV_INDEX* nvIndex = NvGetIndexInfo(handle, NULL);
                if(nvIndex == NULL)
                {
                    if(!_plat__IsNvVirtualIndex(handle))
                    {
                        FAIL_IMMEDIATE(FATAL_ERROR_INTERNAL, TPM_RH_NULL);
                    }
                    else
                    {
                        NV_INDEX tempNvIndex = {0};
                        _plat__NvVirtual_PopulateNvIndexInfo(
                            handle, &tempNvIndex.publicArea, &tempNvIndex.authValue);
                        nvIndex = &tempNvIndex;
                    }
                }
                // nvIndex guaranteed non-null at this point.

                // If only the platform can delete the index, then it is
                // considered to be in the platform hierarchy, otherwise it
                // is in the owner hierarchy.
                if(nvIndex != NULL
                   && IS_ATTRIBUTE(
                       nvIndex->publicArea.attributes, TPMA_NV, PLATFORMCREATE))
                {
                    hierarchy = TPM_RH_PLATFORM;
                }
                else
                {
                    hierarchy = TPM_RH_OWNER;
                }
            }
            break;
        case TPM_HT_TRANSIENT:
            // hierarchy for an object
            {
                OBJECT* object;
                object = HandleToObject(handle);
                VERIFY(object != NULL, FATAL_ERROR_ASSERT, TPM_RH_NULL);

                if(object->attributes.ppsHierarchy)
                {
                    hierarchy = TPM_RH_PLATFORM;
                }
                else if(object->attributes.epsHierarchy)
                {
                    hierarchy = TPM_RH_ENDORSEMENT;
                }
                else if(object->attributes.spsHierarchy)
                {
                    hierarchy = TPM_RH_OWNER;
                }
            }
            break;
        case TPM_HT_PCR:
            hierarchy = TPM_RH_OWNER;
            break;
        default:
            FAIL(FATAL_ERROR_INTERNAL);
            break;
    }
    // this is unreachable but it provides a return value for the default
    // case which makes the complier happy
    return hierarchy;
}