#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "NV_Certify_fp.h"

#if CC_NV_Certify  // Conditional expansion of this file

/*(See part 3 specification)
// certify the contents of an NV index or portion of an NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to read from the Index
//                                      referenced by 'nvIndex'
//      TPM_RC_KEY                      'signHandle' does not reference a signing
//                                      key
//      TPM_RC_NV_LOCKED                Index referenced by 'nvIndex' is locked
//                                      for reading
//      TPM_RC_NV_RANGE                 'offset' plus 'size' extends outside of the
//                                      data range of the Index referenced by
//                                      'nvIndex'
//      TPM_RC_NV_UNINITIALIZED         Index referenced by 'nvIndex' has not been
//                                      written
//      TPM_RC_SCHEME                   'inScheme' is not an allowed value for the
//                                      key definition
TPM_RC
TPM2_NV_Certify(NV_Certify_In*  in,  // IN: input parameter list
                NV_Certify_Out* out  // OUT: output parameter list
)
{
    TPM_RC      result;
    NV_REF      locator;
    NV_INDEX*   nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPMS_ATTEST certifyInfo;
    OBJECT*     signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_NV_Certify_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_NV_Certify_inScheme;

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvReadAccessChecks(
        in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // make sure that the selection is within the range of the Index (cast to avoid
    // any wrap issues with addition)
    if((UINT32)in->size + (UINT32)in->offset > (UINT32)nvIndex->publicArea.dataSize)
        return TPM_RC_NV_RANGE;
    // Make sure the data will fit the return buffer.
    // NOTE: This check may be modified if the output buffer will not hold the
    // maximum sized NV buffer as part of the certified data. The difference in
    // size could be substantial if the signature scheme was produced a large
    // signature (e.g., RSA 4096).
    if(in->size > MAX_NV_BUFFER_SIZE)
        return TPM_RCS_VALUE + RC_NV_Certify_size;

    // Command Output

    // Fill in attest information common fields
    FillInAttestInfo(
        in->signHandle, &in->inScheme, &in->qualifyingData, &certifyInfo);

    // Get the name of the index
    NvGetIndexName(nvIndex, &certifyInfo.attested.nv.indexName);

    // See if this is old format or new format
    if((in->size != 0) || (in->offset != 0))
    {
        // NV certify specific fields
        // Attestation type
        certifyInfo.type = TPM_ST_ATTEST_NV;

        // Set the return size
        certifyInfo.attested.nv.nvContents.t.size = in->size;

        // Set the offset
        certifyInfo.attested.nv.offset = in->offset;

        // Perform the read
        NvGetIndexData(nvIndex,
                       locator,
                       in->offset,
                       in->size,
                       certifyInfo.attested.nv.nvContents.t.buffer);
    }
    else
    {
        HASH_STATE hashState;
        // This is to sign a digest of the data
        certifyInfo.type = TPM_ST_ATTEST_NV_DIGEST;
        // Initialize the hash before calling the function to add the Index data to
        // the hash.
        certifyInfo.attested.nvDigest.nvDigest.t.size =
            CryptHashStart(&hashState, in->inScheme.details.any.hashAlg);
        NvHashIndexData(
            &hashState, nvIndex, locator, 0, nvIndex->publicArea.dataSize);
        CryptHashEnd2B(&hashState, &certifyInfo.attested.nvDigest.nvDigest.b);
    }
    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject,
                          &in->inScheme,
                          &certifyInfo,
                          &in->qualifyingData,
                          &out->certifyInfo,
                          &out->signature);
}

#endif  // CC_NV_Certify