//** Includes
#include "Platform.h"

//** Functions

//***_plat__LocalityGet()
// Get the most recent command locality in locality value form.
// This is an integer value for locality and not a locality structure
// The locality can be 0-4 or 32-255. 5-31 is not allowed.
LIB_EXPORT unsigned char _plat__LocalityGet(void)
{
    return s_locality;
}

//***_plat__LocalitySet()
// Set the most recent command locality in locality value form
LIB_EXPORT void _plat__LocalitySet(unsigned char locality)
{
    if(locality > 4 && locality < 32)
        locality = 0;
    s_locality = locality;
    return;
}