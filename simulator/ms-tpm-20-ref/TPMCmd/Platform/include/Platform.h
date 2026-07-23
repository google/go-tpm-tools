
#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <TpmConfiguration/TpmBuildSwitches.h>
#include <TpmConfiguration/TpmProfile.h>
// TODO_RENAME_INC_FOLDER: public refers to the TPM_CoreLib public headers
#include <tpm_public/BaseTypes.h>
#include <tpm_public/TPMB.h>
#include <tpm_public/MinMax.h>

#include "PlatformACT.h"
#include "PlatformClock.h"
#include "PlatformData.h"
#include "prototypes/platform_public_interface.h"
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/tpm_to_platform_interface.h>
#include <platform_interface/platform_to_tpm_interface.h>
#include "PlatformInternal.h"

#define GLOBAL_C
#define NV_C
#include <platform_interface/pcrstruct.h>
#include <platform_interface/prototypes/platform_pcr_fp.h>

#endif  // _PLATFORM_H_
