/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 04:23:27PM
 */

#ifndef _NV_RESERVED_FP_H_
#define _NV_RESERVED_FP_H_

//*** NvCheckState()
// Function to check the NV state by accessing the platform-specific function
// to get the NV state.  The result state is registered in s_NvIsAvailable
// that will be reported by NvIsAvailable.
//
// This function is called at the beginning of ExecuteCommand before any potential
// check of g_NvStatus.
void NvCheckState(void);

//*** NvCommit
// This is a wrapper for the platform function to commit pending NV writes.
BOOL NvCommit(void);

//*** NvPowerOn()
//  This function is called at _TPM_Init to initialize the NV environment.
//  Return Type: BOOL
//      TRUE(1)         all NV was initialized
//      FALSE(0)        the NV containing saved state had an error and
//                      TPM2_Startup(CLEAR) is required
BOOL NvPowerOn(void);

//*** NvManufacture()
// This function initializes the NV system at pre-install time.
//
// This function should only be called in a manufacturing environment or in a
// simulation.
//
// The layout of NV memory space is an implementation choice.
void NvManufacture(void);

//*** NvRead()
// This function is used to move reserved data from NV memory to RAM.
void NvRead(void*  outBuffer,  // OUT: buffer to receive data
            UINT32 nvOffset,   // IN: offset in NV of value
            UINT32 size        // IN: size of the value to read
);

//*** NvWrite()
// This function is used to post reserved data for writing to NV memory. Before
// the TPM completes the operation, the value will be written.
BOOL NvWrite(UINT32 nvOffset,  // IN: location in NV to receive data
             UINT32 size,      // IN: size of the data to move
             void*  inBuffer   // IN: location containing data to write
);

//*** NvUpdatePersistent()
// This function is used to update a value in the PERSISTENT_DATA structure and
// commits the value to NV.
void NvUpdatePersistent(
    UINT32 offset,  // IN: location in PERMANENT_DATA to be updated
    UINT32 size,    // IN: size of the value
    void*  buffer   // IN: the new data
);

//*** NvClearPersistent()
// This function is used to clear a persistent data entry and commit it to NV
void NvClearPersistent(UINT32 offset,  // IN: the offset in the PERMANENT_DATA
                                       //     structure to be cleared (zeroed)
                       UINT32 size     // IN: number of bytes to clear
);

//*** NvReadPersistent()
// This function reads persistent data to the RAM copy of the 'gp' structure.
void NvReadPersistent(void);

#endif  // _NV_RESERVED_FP_H_
