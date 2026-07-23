
#ifndef _MANUFACTURE_FP_H_
#define _MANUFACTURE_FP_H_

//*** TPM_Manufacture()
// This function initializes the TPM values in preparation for the TPM's first
// use. This function will fail if previously called. The TPM can be re-manufactured
// by calling TPM_Teardown() first and then calling this function again.
// NV must be enabled first (typically with NvPowerOn() via _TPM_Init)
//
// return type: int
//      -2          NV System not available
//      -1          FAILURE - System is incorrectly compiled.
//      0           success
//      1           manufacturing process previously performed
// returns
#define MANUF_NV_NOT_READY   (-2)
#define MANUF_INVALID_CONFIG (-1)
#define MANUF_OK             0
#define MANUF_ALREADY_DONE   1
// params
#define MANUF_FIRST_TIME    1
#define MANUF_REMANUFACTURE 0
LIB_EXPORT int TPM_Manufacture(
    int firstTime  // IN: indicates if this is the first call from
                   //     main()
);

//*** TPM_TearDown()
// This function prepares the TPM for re-manufacture. It should not be implemented
// in anything other than a simulated TPM.
//
// In this implementation, all that is needs is to stop the cryptographic units
// and set a flag to indicate that the TPM can be re-manufactured. This should
// be all that is necessary to start the manufacturing process again.
//  Return Type: int
//      0        success
//      1        TPM not previously manufactured
#define TEARDOWN_OK          0
#define TEARDOWN_NOTHINGDONE 1
LIB_EXPORT int TPM_TearDown(void);

//*** TpmEndSimulation()
// This function is called at the end of the simulation run. It is used to provoke
// printing of any statistics that might be needed.
LIB_EXPORT void TpmEndSimulation(void);

#endif  // _MANUFACTURE_FP_H_
