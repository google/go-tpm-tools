# TPM Include Files

The TPM include files are split into three rough categories:

1. tpm_public - these are the public headers that consumers of the TPM Core
   library should include. For example, the Simulator and Platform libraries
   depend on this information.
2. private - These are intended to be private to the TPM Core, though there are
   some current cases that still need to be cleaned up where the platform peeks
   under the covers.
3. platform_interface - these headers declare the interface the TPM provides-to
   and expects-from the Platform library.
