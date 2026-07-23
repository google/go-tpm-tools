
// common headers for simulator implementation files

#ifndef SIMULATOR_PRIVATE_H
#define SIMULATOR_PRIVATE_H

//** Includes, Locals, Defines and Function Prototypes
#include <tpm_public/tpm_public.h>

#include "simulator_sysheaders.h"

// TODO_RENAME_INC_FOLDER:prototypes refers to the platform library
#include <prototypes/platform_public_interface.h>
// TODO_RENAME_INC_FOLDER:platform_interface refers to the TPM_CoreLib platform interface
#include <platform_interface/tpm_to_platform_interface.h>
#include <platform_interface/platform_to_tpm_interface.h>

#include "TpmTcpProtocol.h"
#include "Simulator_fp.h"

#endif  // SIMULATOR_PRIVATE_H
