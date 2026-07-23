#include "Platform.h"
#include <tpm_public/TpmAlgorithmDefines.h>
#include <tpm_public/TpmTypes.h>

LIB_EXPORT void _plat_GetEnabledSelfTest(
    uint8_t  fullTest,         // IN: full test or not
    uint8_t* pToTestVector,    // INOUT: initialized byte array of tracked tests
    size_t   toTestVectorSize  // IN: size of the byte array in bytes
)
{
    (void)fullTest;
    (void)pToTestVector;
    (void)toTestVectorSize;
}
