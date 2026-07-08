//** Description
//
// This file contains routines that are called by the core library to allow the
// platform to use the Core storage structures for small amounts of related data.
//
// In this implementation, the buffers are all just set to 0xFF

//** Includes and Data Definitions
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "Platform.h"

//** _plat__GetPlatformManufactureData

// This function allows the platform to provide a small amount of data to be
// stored as part of the TPM's PERSISTENT_DATA structure during manufacture.  Of
// course the platform can store data separately as well, but this allows a
// simple platform implementation to store a few bytes of data without
// implementing a multi-layer storage system.  This function is called on
// manufacture and CLEAR.  The buffer will contain the last value provided
// to the Core library.
LIB_EXPORT void _plat__GetPlatformManufactureData(uint8_t* pPlatformPersistentData,
                                                  uint32_t bufferSize)
{
    if(bufferSize != 0)
    {
        memset((void*)pPlatformPersistentData, 0xFF, bufferSize);
    }
}
