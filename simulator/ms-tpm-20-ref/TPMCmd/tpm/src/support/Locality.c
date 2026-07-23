//** Includes
#include "Tpm.h"

//** LocalityGetAttributes()
// This function will convert a locality expressed as an integer into
// TPMA_LOCALITY form.
//
// The function returns the locality attribute.
TPMA_LOCALITY
LocalityGetAttributes(UINT8 locality  // IN: locality value
)
{
    TPMA_LOCALITY locality_attributes;
    BYTE*         localityAsByte = (BYTE*)&locality_attributes;

    MemorySet(&locality_attributes, 0, sizeof(TPMA_LOCALITY));
    switch(locality)
    {
        case 0:
            SET_ATTRIBUTE(locality_attributes, TPMA_LOCALITY, TPM_LOC_ZERO);
            break;
        case 1:
            SET_ATTRIBUTE(locality_attributes, TPMA_LOCALITY, TPM_LOC_ONE);
            break;
        case 2:
            SET_ATTRIBUTE(locality_attributes, TPMA_LOCALITY, TPM_LOC_TWO);
            break;
        case 3:
            SET_ATTRIBUTE(locality_attributes, TPMA_LOCALITY, TPM_LOC_THREE);
            break;
        case 4:
            SET_ATTRIBUTE(locality_attributes, TPMA_LOCALITY, TPM_LOC_FOUR);
            break;
        default:
            VERIFY(locality > 31, FATAL_ERROR_ASSERT, 0);
            *localityAsByte = locality;
            break;
    }
    return locality_attributes;
}