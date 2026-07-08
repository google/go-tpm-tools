//** Description
// This file contains the function that performs the "manufacturing" of the TPM
// in a simulated environment. These functions should not be used outside of
// a manufacturing or simulation environment.

//** Includes and Data Definitions
#define MANUFACTURE_C
#include "Tpm.h"
#include "TpmSizeChecks_fp.h"

//** Functions

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
LIB_EXPORT int TPM_Manufacture(
    int firstTime  // IN: indicates if this is the first call from
                   //     main()
)
{
    TPM_SU orderlyShutdown;

#if RUNTIME_SIZE_CHECKS
    // Call the function to verify the sizes of values that result from different
    // compile options.
    if(!TpmSizeChecks())
        return MANUF_INVALID_CONFIG;
#endif
#if LIBRARY_COMPATIBILITY_CHECK
    // Make sure that the attached library performs as expected.
    if(!ExtMath_Debug_CompatibilityCheck())
        return MANUF_INVALID_CONFIG;
#endif

    // If TPM has been manufactured, return indication.
    if(!firstTime && g_manufactured)
        return MANUF_ALREADY_DONE;

    // trigger failure mode if called in error.
    int nvReadyState = _plat__GetNvReadyState();
    pAssert_NORET(nvReadyState == NV_READY);  // else failure mode
    if(nvReadyState != NV_READY)
    {
        return MANUF_NV_NOT_READY;
    }

    // Do power on initializations of the cryptographic libraries.
    CryptInit();

    s_DAPendingOnNV = FALSE;

    // initialize NV
    NvManufacture();

    // Clear the magic value in the DRBG state
    go.drbgState.magic = 0;

    CryptStartup(SU_RESET);

    // default configuration for PCR
    PCRManufacture();

    // initialize pre-installed hierarchy data
    // This should happen after NV is initialized because hierarchy data is
    // stored in NV.
    HierarchyPreInstall_Init();

    // initialize dictionary attack parameters
    DAPreInstall_Init();

    // initialize PP list
    PhysicalPresencePreInstall_Init();

    // initialize command audit list
    CommandAuditPreInstall_Init();

    // first start up is required to be Startup(CLEAR)
    orderlyShutdown = TPM_SU_CLEAR;
    NV_WRITE_PERSISTENT(orderlyState, orderlyShutdown);

    // initialize the firmware version
    gp.firmwareV1 = _plat__GetTpmFirmwareVersionHigh();
    gp.firmwareV2 = _plat__GetTpmFirmwareVersionLow();

    _plat__GetPlatformManufactureData(gp.platformReserved,
                                      sizeof(gp.platformReserved));
    NV_SYNC_PERSISTENT(platformReserved);

    NV_SYNC_PERSISTENT(firmwareV1);
    NV_SYNC_PERSISTENT(firmwareV2);

    // initialize the total reset counter to 0
    gp.totalResetCount = 0;
    NV_SYNC_PERSISTENT(totalResetCount);

    // initialize the clock stuff
    go.clock     = 0;
    go.clockSafe = YES;

    NvWrite(NV_ORDERLY_DATA, sizeof(ORDERLY_DATA), &go);

    // Commit NV writes.  Manufacture process is an artificial process existing
    // only in simulator environment and it is not defined in the specification
    // that what should be the expected behavior if the NV write fails at this
    // point.  Therefore, it is assumed the NV write here is always success and
    // no return code of this function is checked.
    NvCommit();

    g_manufactured = TRUE;

    return MANUF_OK;
}

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
LIB_EXPORT int TPM_TearDown(void)
{
    g_manufactured = FALSE;
    g_initCompleted = FALSE;
    _plat__TearDown();
    return TEARDOWN_OK;
}

//*** TpmEndSimulation()
// This function is called at the end of the simulation run. It is used to provoke
// printing of any statistics that might be needed.
LIB_EXPORT void TpmEndSimulation(void)
{
#if SIMULATION
    HashLibSimulationEnd();
    SymLibSimulationEnd();
    MathLibSimulationEnd();
#  if ALG_RSA
    RsaSimulationEnd();
#  endif
#  if ALG_ECC
    EccSimulationEnd();
#  endif
#endif  // SIMULATION
}