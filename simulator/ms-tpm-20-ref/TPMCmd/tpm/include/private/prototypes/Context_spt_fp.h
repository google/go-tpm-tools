/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CONTEXT_SPT_FP_H_
#define _CONTEXT_SPT_FP_H_

//*** ComputeContextProtectionKey()
// This function retrieves the symmetric protection key for context encryption
// It is used by TPM2_ConextSave and TPM2_ContextLoad to create the symmetric
// encryption key and iv
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextProtectionKey(TPMS_CONTEXT*  contextBlob,  // IN: context blob
                                   TPM2B_SYM_KEY* symKey,  // OUT: the symmetric key
                                   TPM2B_IV*      iv       // OUT: the IV.
);

//*** ComputeContextIntegrity()
// Generate the integrity hash for a context
//       It is used by TPM2_ContextSave to create an integrity hash
//       and by TPM2_ContextLoad to compare an integrity hash
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextIntegrity(TPMS_CONTEXT* contextBlob,  // IN: context blob
                               TPM2B_DIGEST* integrity     // OUT: integrity
);

//*** SequenceDataExport()
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataExport(
    HASH_OBJECT*        object,       // IN: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // OUT: a sequence context in a buffer
);

//*** SequenceDataImport()
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataImport(
    HASH_OBJECT*        object,       // IN/OUT: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // IN/OUT: a sequence context in a buffer
);

#endif  // _CONTEXT_SPT_FP_H_
