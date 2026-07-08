#include "Tpm.h"
#include "PolicyCapability_fp.h"
#include "Policy_spt_fp.h"
#include "ACT_spt_fp.h"
#include "AlgorithmCap_fp.h"
#include "CommandAudit_fp.h"
#include "CommandCodeAttributes_fp.h"
#include "CryptEccMain_fp.h"
#include "Handle_fp.h"
#include "NvDynamic_fp.h"
#include "Object_fp.h"
#include "PCR_fp.h"
#include "PP_fp.h"
#include "PropertyCap_fp.h"
#include "Session_fp.h"

#if CC_PolicyCapability  // Conditional expansion of this file

/*(See part 3 specification)
// This command performs an immediate policy assertion against the current
// value of a TPM Capability.
*/
//  Return Type: TPM_RC
//      TPM_RC_HANDLE       value of 'property' is in an unsupported handle range
//                          for the TPM_CAP_HANDLES 'capability' value
//      TPM_RC_VALUE        invalid 'capability'; or 'property' is not 0 for the
//                          TPM_CAP_PCRS 'capability' value
//      TPM_RC_SIZE         'operandB' is larger than the size of the capability
//                          data minus 'offset'.
TPM_RC
TPM2_PolicyCapability(PolicyCapability_In* in  // IN: input parameter list
)
{
    union
    {
        TPMS_ALG_PROPERTY      alg;
        TPM_HANDLE             handle;
        TPMA_CC                commandAttributes;
        TPM_CC                 command;
        TPMS_TAGGED_PCR_SELECT pcrSelect;
        TPMS_TAGGED_PROPERTY   tpmProperty;
#  if ALG_ECC
        TPM_ECC_CURVE curve;
#  endif  // ALG_ECC
        TPMS_TAGGED_POLICY policy;
#  if ACT_SUPPORT
        TPMS_ACT_DATA act;
#  endif  // ACT_SUPPORT
    } propertyUnion;

    SESSION*     session;
    BYTE         propertyData[sizeof(propertyUnion)];
    UINT16       propertySize = 0;
    BYTE*        buffer       = propertyData;
    INT32        bufferSize   = sizeof(propertyData);
    TPM_CC       commandCode  = TPM_CC_PolicyCapability;
    HASH_STATE   hashState;
    TPM2B_DIGEST argHash;

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    if(session->attributes.isTrialPolicy == CLEAR)
    {
        switch(in->capability)
        {
            case TPM_CAP_ALGS:
                if(AlgorithmCapGetOneImplemented((TPM_ALG_ID)in->property,
                                                 &propertyUnion.alg))
                {
                    propertySize = TPMS_ALG_PROPERTY_Marshal(
                        &propertyUnion.alg, &buffer, &bufferSize);
                }
                break;
            case TPM_CAP_HANDLES:
            {
                BOOL foundHandle = FALSE;
                switch(HandleGetType((TPM_HANDLE)in->property))
                {
                    case TPM_HT_TRANSIENT:
                        foundHandle = ObjectCapGetOneLoaded((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_PERSISTENT:
                        foundHandle = NvCapGetOnePersistent((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_NV_INDEX:
                        foundHandle = NvCapGetOneIndex((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_LOADED_SESSION:
                        foundHandle =
                            SessionCapGetOneLoaded((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_SAVED_SESSION:
                        foundHandle = SessionCapGetOneSaved((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_PCR:
                        foundHandle = PCRCapGetOneHandle((TPM_HANDLE)in->property);
                        break;
                    case TPM_HT_PERMANENT:
                        foundHandle =
                            PermanentCapGetOneHandle((TPM_HANDLE)in->property);
                        break;
                    default:
                        // Unsupported input handle type
                        return TPM_RCS_HANDLE + RC_PolicyCapability_property;
                        break;
                }
                if(foundHandle)
                {
                    TPM_HANDLE handle = (TPM_HANDLE)in->property;
                    propertySize = TPM_HANDLE_Marshal(&handle, &buffer, &bufferSize);
                }
                break;
            }
            case TPM_CAP_COMMANDS:
                if(CommandCapGetOneCC((TPM_CC)in->property,
                                      &propertyUnion.commandAttributes))
                {
                    propertySize = TPMA_CC_Marshal(
                        &propertyUnion.commandAttributes, &buffer, &bufferSize);
                }
                break;
            case TPM_CAP_PP_COMMANDS:
                if(PhysicalPresenceCapGetOneCC((TPM_CC)in->property))
                {
                    TPM_CC cc    = (TPM_CC)in->property;
                    propertySize = TPM_CC_Marshal(&cc, &buffer, &bufferSize);
                }
                break;
            case TPM_CAP_AUDIT_COMMANDS:
                if(CommandAuditCapGetOneCC((TPM_CC)in->property))
                {
                    TPM_CC cc    = (TPM_CC)in->property;
                    propertySize = TPM_CC_Marshal(&cc, &buffer, &bufferSize);
                }
                break;
            // NOTE: TPM_CAP_PCRS can't work for PolicyCapability since CAP_PCRS
            // requires property to be 0 and always returns all the PCR banks.
            case TPM_CAP_PCR_PROPERTIES:
                if(PCRGetProperty((TPM_PT_PCR)in->property, &propertyUnion.pcrSelect))
                {
                    propertySize = TPMS_TAGGED_PCR_SELECT_Marshal(
                        &propertyUnion.pcrSelect, &buffer, &bufferSize);
                }
                break;
            case TPM_CAP_TPM_PROPERTIES:
                if(TPMCapGetOneProperty((TPM_PT)in->property,
                                        &propertyUnion.tpmProperty))
                {
                    propertySize = TPMS_TAGGED_PROPERTY_Marshal(
                        &propertyUnion.tpmProperty, &buffer, &bufferSize);
                }
                break;
#  if ALG_ECC
            case TPM_CAP_ECC_CURVES:
            {
                TPM_ECC_CURVE curve = (TPM_ECC_CURVE)in->property;
                if(CryptCapGetOneECCCurve(curve))
                {
                    propertySize =
                        TPM_ECC_CURVE_Marshal(&curve, &buffer, &bufferSize);
                }
                break;
            }
#  endif  // ALG_ECC
            case TPM_CAP_AUTH_POLICIES:
                if(HandleGetType((TPM_HANDLE)in->property) != TPM_HT_PERMANENT)
                    return TPM_RCS_VALUE + RC_PolicyCapability_property;
                if(PermanentHandleGetOnePolicy((TPM_HANDLE)in->property,
                                               &propertyUnion.policy))
                {
                    propertySize = TPMS_TAGGED_POLICY_Marshal(
                        &propertyUnion.policy, &buffer, &bufferSize);
                }
                break;
#  if ACT_SUPPORT
            case TPM_CAP_ACT:
                if(((TPM_RH)in->property < TPM_RH_ACT_0)
                   || ((TPM_RH)in->property > TPM_RH_ACT_F))
                    return TPM_RCS_VALUE + RC_PolicyCapability_property;
                if(ActGetOneCapability((TPM_HANDLE)in->property, &propertyUnion.act))
                {
                    propertySize = TPMS_ACT_DATA_Marshal(
                        &propertyUnion.act, &buffer, &bufferSize);
                }
                break;
#  endif  // ACT_SUPPORT
            case TPM_CAP_VENDOR_PROPERTY:
                // vendor property is not implemented
            default:
                // Unsupported TPM_CAP value
                return TPM_RCS_VALUE + RC_PolicyCapability_capability;
                break;
        }

        if(propertySize == 0)
        {
            // A property that doesn't exist trivially satisfies NEQ, and
            // trivially can't satisfy any other operation.
            if(in->operation != TPM_EO_NEQ)
            {
                return TPM_RC_POLICY;
            }
        }
        else
        {
            // The property was found, so we need to perform the comparison.

            // Make sure that offset is within range
            if(in->offset > propertySize)
            {
                return TPM_RCS_VALUE + RC_PolicyCapability_offset;
            }

            // Property data size should not be smaller than input operandB size
            if((propertySize - in->offset) < in->operandB.t.size)
            {
                return TPM_RCS_SIZE + RC_PolicyCapability_operandB;
            }

            if(!PolicySptCheckCondition(in->operation,
                                        propertyData + in->offset,
                                        in->operandB.t.buffer,
                                        in->operandB.t.size))
            {
                return TPM_RC_POLICY;
            }
        }
    }
    // Internal Data Update

    // Start argument hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);

    //  add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);

    //  add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);

    //  add capability
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CAP), in->capability);

    //  add property
    CryptDigestUpdateInt(&hashState, sizeof(UINT32), in->property);

    //  complete argument digest
    CryptHashEnd2B(&hashState, &argHash.b);

    // Update policyDigest
    //  Start digest
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCapability