#include "Tpm.h"
#include "GetCapability_fp.h"

#if CC_GetCapability  // Conditional expansion of this file

/*(See part 3 specification)
// This command returns various information regarding the TPM and its current
// state
*/
//  Return Type: TPM_RC
//      TPM_RC_HANDLE       value of 'property' is in an unsupported handle range
//                          for the TPM_CAP_HANDLES 'capability' value
//      TPM_RC_VALUE        invalid 'capability'; or 'property' is not 0 for the
//                          TPM_CAP_PCRS 'capability' value
TPM_RC
TPM2_GetCapability(GetCapability_In*  in,  // IN: input parameter list
                   GetCapability_Out* out  // OUT: output parameter list
)
{
    TPMU_CAPABILITIES* data = &out->capabilityData.data;
    // Command Output

    // Set output capability type the same as input type
    out->capabilityData.capability = in->capability;

    switch(in->capability)
    {
        case TPM_CAP_ALGS:
            out->moreData = AlgorithmCapGetImplemented(
                (TPM_ALG_ID)in->property, in->propertyCount, &data->algorithms);
            break;
        case TPM_CAP_HANDLES:
            switch(HandleGetType((TPM_HANDLE)in->property))
            {
                case TPM_HT_TRANSIENT:
                    // Get list of handles of loaded transient objects
                    out->moreData = ObjectCapGetLoaded(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_PERSISTENT:
                    // Get list of handles of persistent objects
                    out->moreData = NvCapGetPersistent(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_NV_INDEX:
                    // Get list of defined NV index
                    out->moreData = NvCapGetIndex(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_LOADED_SESSION:
                    // Get list of handles of loaded sessions
                    out->moreData = SessionCapGetLoaded(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_SAVED_SESSION:
                    // Get list of handles of
                    out->moreData = SessionCapGetSaved(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_PCR:
                    // Get list of handles of PCR
                    out->moreData = PCRCapGetHandles(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                case TPM_HT_PERMANENT:
                    // Get list of permanent handles
                    out->moreData = PermanentCapGetHandles(
                        (TPM_HANDLE)in->property, in->propertyCount, &data->handles);
                    break;
                default:
                    // Unsupported input handle type
                    return TPM_RCS_HANDLE + RC_GetCapability_property;
                    break;
            }
            break;
        case TPM_CAP_COMMANDS:
            out->moreData = CommandCapGetCCList(
                (TPM_CC)in->property, in->propertyCount, &data->command);
            break;
        case TPM_CAP_PP_COMMANDS:
            out->moreData = PhysicalPresenceCapGetCCList(
                (TPM_CC)in->property, in->propertyCount, &data->ppCommands);
            break;
        case TPM_CAP_AUDIT_COMMANDS:
            out->moreData = CommandAuditCapGetCCList(
                (TPM_CC)in->property, in->propertyCount, &data->auditCommands);
            break;
        case TPM_CAP_PCRS:
            // Input property must be 0
            if(in->property != 0)
                return TPM_RCS_VALUE + RC_GetCapability_property;
            out->moreData =
                PCRCapGetAllocation(in->propertyCount, &data->assignedPCR);
            break;
        case TPM_CAP_PCR_PROPERTIES:
            out->moreData = PCRCapGetProperties(
                (TPM_PT_PCR)in->property, in->propertyCount, &data->pcrProperties);
            break;
        case TPM_CAP_TPM_PROPERTIES:
            out->moreData = TPMCapGetProperties(
                (TPM_PT)in->property, in->propertyCount, &data->tpmProperties);
            break;
#  if ALG_ECC
        case TPM_CAP_ECC_CURVES:
            out->moreData = CryptCapGetECCCurve(
                (TPM_ECC_CURVE)in->property, in->propertyCount, &data->eccCurves);
            break;
#  endif  // ALG_ECC
        case TPM_CAP_AUTH_POLICIES:
            if(HandleGetType((TPM_HANDLE)in->property) != TPM_HT_PERMANENT)
                return TPM_RCS_VALUE + RC_GetCapability_property;
            out->moreData = PermanentHandleGetPolicy(
                (TPM_HANDLE)in->property, in->propertyCount, &data->authPolicies);
            break;
        case TPM_CAP_ACT:
#  if ACT_SUPPORT
            if(((TPM_RH)in->property < TPM_RH_ACT_0)
               || ((TPM_RH)in->property > TPM_RH_ACT_F))
                return TPM_RCS_VALUE + RC_GetCapability_property;
            out->moreData = ActGetCapabilityData(
                (TPM_HANDLE)in->property, in->propertyCount, &data->actData);
            break;
#  else
            return TPM_RCS_VALUE + RC_GetCapability_property;
#  endif  // ACT_SUPPORT
#  if SEC_CHANNEL_SUPPORT
        case TPM_CAP_PUB_KEYS:
            // This reference implementation supports only a single TPM SPDM public key
            if((TPM_PUB_KEY)in->property != TPM_PUB_KEY_TPM_SPDM_00)
                return TPM_RCS_VALUE + RC_GetCapability_property;
            out->moreData = SpdmCapGetTpmPubKeys(
                (TPM_PUB_KEY)in->property, in->propertyCount, &data->pubKeys);
            break;
        case TPM_CAP_SPDM_SESSION_INFO:
            // Input property must be 0
            if(in->property != 0)
                return TPM_RCS_VALUE + RC_GetCapability_property;
            out->moreData = SpdmCapGetSessionInfo(&data->spdmSessionInfo);
            break;
#  endif  // SEC_CHANNEL_SUPPORT
        case TPM_CAP_VENDOR_PROPERTY:
            // vendor property is not implemented
        default:
            // Unsupported TPM_CAP value
            return TPM_RCS_VALUE + RC_GetCapability_capability;
            break;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_GetCapability