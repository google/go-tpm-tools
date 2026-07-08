//** Description
//
//  This module simulates the cancel pins on the TPM.
//
//** Includes, Typedefs, Structures, and Defines
#include "Platform.h"

//** Functions

//***_plat__IsCanceled()
// Check if the cancel flag is set
//  Return Type: int
//      TRUE(1)         if cancel flag is set
//      FALSE(0)        if cancel flag is not set
LIB_EXPORT int _plat__IsCanceled(void)
{
    // return cancel flag
    return s_isCanceled;
}

//***_plat__SetCancel()

// Set cancel flag.
LIB_EXPORT void _plat__SetCancel(void)
{
    s_isCanceled = TRUE;
    return;
}

//***_plat__ClearCancel()
// Clear cancel flag
LIB_EXPORT void _plat__ClearCancel(void)
{
    s_isCanceled = FALSE;
    return;
}