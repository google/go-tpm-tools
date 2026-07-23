//** Introduction
//
// This file contains the implementation of the message authentication codes based
// on a symmetric block cipher. These functions only use the single block
// encryption functions of the selected symmetric cryptographic library.

//** Includes, Defines, and Typedefs
#define _CRYPT_HASH_C_
#include "Tpm.h"

#if SMAC_IMPLEMENTED

//*** CryptSmacStart()
// Function to start an SMAC.
UINT16
CryptSmacStart(HASH_STATE*        state,
               TPMU_PUBLIC_PARMS* keyParameters,
               TPM_ALG_ID         macAlg,  // IN: the type of MAC
               TPM2B*             key)
{
    UINT16 retVal = 0;
    //
    // Make sure that the key size is correct. This should have been checked
    // at key load, but...
    if(BITS_TO_BYTES(keyParameters->symDetail.sym.keyBits.sym) == key->size)
    {
        switch(macAlg)
        {
#  if ALG_CMAC
            case TPM_ALG_CMAC:
                retVal =
                    CryptCmacStart(&state->state.smac, keyParameters, macAlg, key);
                break;
#  endif
            default:
                break;
        }
    }
    state->type = (retVal != 0) ? HASH_STATE_SMAC : HASH_STATE_EMPTY;
    return retVal;
}

//*** CryptMacStart()
// Function to start either an HMAC or an SMAC. Cannot reuse the CryptHmacStart
// function because of the difference in number of parameters.
UINT16
CryptMacStart(HMAC_STATE*        state,
              TPMU_PUBLIC_PARMS* keyParameters,
              TPM_ALG_ID         macAlg,  // IN: the type of MAC
              TPM2B*             key)
{
    MemorySet(state, 0, sizeof(HMAC_STATE));
    if(CryptHashIsValidAlg(macAlg, FALSE))
    {
        return CryptHmacStart(state, macAlg, key->size, key->buffer);
    }
    else if(CryptSmacIsValidAlg(macAlg, FALSE))
    {
        return CryptSmacStart(&state->hashState, keyParameters, macAlg, key);
    }
    else
        return 0;
}

//*** CryptMacEnd()
// Dispatch to the MAC end function using a size and buffer pointer.
UINT16
CryptMacEnd(HMAC_STATE* state, UINT32 size, BYTE* buffer)
{
    UINT16 retVal = 0;
    if(state->hashState.type == HASH_STATE_SMAC)
        retVal = (state->hashState.state.smac.smacMethods.end)(
            &state->hashState.state.smac.state, size, buffer);
    else if(state->hashState.type == HASH_STATE_HMAC)
        retVal = CryptHmacEnd(state, size, buffer);
    state->hashState.type = HASH_STATE_EMPTY;
    return retVal;
}

//*** CryptMacEnd2B()
// Dispatch to the MAC end function using a 2B.
UINT16
CryptMacEnd2B(HMAC_STATE* state, TPM2B* data)
{
    return CryptMacEnd(state, data->size, data->buffer);
}
#endif  // SMAC_IMPLEMENTED
