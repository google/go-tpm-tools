//** Introduction
// This file contains the headers necessary to build the tpm big num library.
// TODO_RENAME_INC_FOLDER: public refers to the TPM_CoreLib public headers
#include <tpm_public/tpm_public.h>
#include <tpm_public/prototypes/TpmFail_fp.h>
// TODO_RENAME_INC_FOLDER: private refers to the TPM_CoreLib private(protected) headers
#include <tpm_public/TpmAlgorithmDefines.h>
#include <tpm_public/GpMacros.h>  // required for TpmFail_fp.h
#include <tpm_public/Capabilities.h>
#include <tpm_public/TpmTypes.h>  // requires capabilities & GpMacros
#include <TpmBigNum/TpmToTpmBigNumMath.h>
#include "BnSupport_Interface.h"
#include "BnConvert_fp.h"
#include "BnMemory_fp.h"
#include "BnMath_fp.h"
#include "BnUtil_fp.h"
#include <MathLibraryInterface.h>