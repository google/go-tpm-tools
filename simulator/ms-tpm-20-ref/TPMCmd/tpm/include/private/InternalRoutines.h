#ifndef INTERNAL_ROUTINES_H
#define INTERNAL_ROUTINES_H

#if !defined _LIB_SUPPORT_H_ && !defined _TPM_H_
#  error "Should not be called"
#endif

// DRTM functions
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/prototypes/_TPM_Hash_Start_fp.h>
#include <platform_interface/prototypes/_TPM_Hash_Data_fp.h>
#include <platform_interface/prototypes/_TPM_Hash_End_fp.h>

// Internal subsystem functions
#include "Object_fp.h"
#include "Context_spt_fp.h"
#include "Object_spt_fp.h"
#include "Entity_fp.h"
#include "Session_fp.h"
#include "Hierarchy_fp.h"
#include "NvReserved_fp.h"
#include "NvDynamic_fp.h"
#include "NV_spt_fp.h"
#include "ACT_spt_fp.h"
#include "PCR_fp.h"
#include "DA_fp.h"
#if SEC_CHANNEL_SUPPORT
#  include "SecChannel_fp.h"
#endif  // SEC_CHANNEL_SUPPORT
// TODO_RENAME_INC_FOLDER: public refers to the TPM_CoreLib public headers
#include <tpm_public/prototypes/TpmFail_fp.h>
#include "SessionProcess_fp.h"

// Internal support functions
#include "CommandCodeAttributes_fp.h"
#include "Marshal.h"
#include "Time_fp.h"
#include "Locality_fp.h"
#include "PP_fp.h"
#include "CommandAudit_fp.h"
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/prototypes/Manufacture_fp.h>
#include "Handle_fp.h"
#include "Power_fp.h"
#include "Response_fp.h"
#include "CommandDispatcher_fp.h"

#ifdef CC_AC_Send
#  include "AC_spt_fp.h"
#endif  // CC_AC_Send

// Miscellaneous
#include "Bits_fp.h"
#include "AlgorithmCap_fp.h"
#include "PropertyCap_fp.h"
#include "IoBuffers_fp.h"
#include "Memory_fp.h"
#include "ResponseCodeProcessing_fp.h"

// Asymmetric Support library Interface
// TODO_RENAME_INC_FOLDER: needs a component prefix
// Math interface must be included before other Crypt headers to define types
#include <MathLibraryInterface.h>

// Internal cryptographic functions
#include "Ticket_fp.h"
#include "CryptUtil_fp.h"
#include "CryptHash_fp.h"
#include "CryptSym_fp.h"
#include "CryptPrime_fp.h"
#include "CryptRand_fp.h"
#include "CryptSelfTest_fp.h"
#include "MathOnByteBuffers_fp.h"
#include "CryptSym_fp.h"
#include "AlgorithmTests_fp.h"

#if ALG_RSA
#  include "CryptRsa_fp.h"
#  include "CryptPrimeSieve_fp.h"
#endif

#if ALG_ECC
#  include "CryptEccMain_fp.h"
#  include "CryptEccSignature_fp.h"
#  include "CryptEccKeyExchange_fp.h"
#  include "CryptEccCrypt_fp.h"
#endif

#if CC_MAC || CC_MAC_Start
#  include "CryptSmac_fp.h"
#  if ALG_CMAC
#    include "CryptCmac_fp.h"
#  endif
#endif

// Linkage to platform functions
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/tpm_to_platform_interface.h>

#endif
