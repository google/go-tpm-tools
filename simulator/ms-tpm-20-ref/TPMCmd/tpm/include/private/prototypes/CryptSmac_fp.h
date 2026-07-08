/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _CRYPT_SMAC_FP_H_
#define _CRYPT_SMAC_FP_H_

#if SMAC_IMPLEMENTED

//*** CryptSmacStart()
// Function to start an SMAC.
UINT16
CryptSmacStart(HASH_STATE*        state,
               TPMU_PUBLIC_PARMS* keyParameters,
               TPM_ALG_ID         macAlg,  // IN: the type of MAC
               TPM2B*             key);

//*** CryptMacStart()
// Function to start either an HMAC or an SMAC. Cannot reuse the CryptHmacStart
// function because of the difference in number of parameters.
UINT16
CryptMacStart(HMAC_STATE*        state,
              TPMU_PUBLIC_PARMS* keyParameters,
              TPM_ALG_ID         macAlg,  // IN: the type of MAC
              TPM2B*             key);

//*** CryptMacEnd()
// Dispatch to the MAC end function using a size and buffer pointer.
UINT16
CryptMacEnd(HMAC_STATE* state, UINT32 size, BYTE* buffer);

//*** CryptMacEnd2B()
// Dispatch to the MAC end function using a 2B.
UINT16
CryptMacEnd2B(HMAC_STATE* state, TPM2B* data);
#endif  // SMAC_IMPLEMENTED

#endif  // _CRYPT_SMAC_FP_H_
