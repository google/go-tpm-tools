####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.16.3)
project(Tpm_CoreLib VERSION 1.62.0 LANGUAGES C)
print_project_info()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# this project builds the static TPM Corelibrary
add_library(Tpm_CoreLib STATIC)
add_library(Tpm_CoreLib::Tpm_CoreLib ALIAS Tpm_CoreLib)

# don't directly link to TPM_PlatformLib because in a library ("parts") build
# (i.e. not a single giant CMake project), the Platform is provided during
# final link.
target_link_libraries(Tpm_CoreLib PRIVATE
    TpmConfiguration
    Tpm_Public_Headers
    Tpm_Platform_Interface
    Tpm_CryptoLib_TpmBigNum
)
target_link_libraries(Tpm_CoreLib PRIVATE
    Tpm_CryptoLib_Hash_${cryptoLib_Hash}
    Tpm_CryptoLib_Symmetric_${cryptoLib_Symmetric}
    Tpm_CryptoLib_Math_${cryptoLib_BnMath}
)

# allow lazy references into header folders for TpmCoreLib to
# maintain compat
target_include_directories(Tpm_CoreLib PRIVATE
    ../include
    ../include/private
    ../include/private/prototypes
    ../include/platform_interface/Tpm_Platform_Interface
    ../include/platform_interface/Tpm_Platform_Interface/prototypes
)
####################################################
# Library
####################################################

# use this smaller build when working on cmake files
# will result in unresolved externals at final
# simulator link step, but saves a lot of build time
# when working on includes, packages, and the like
# function(test_generate_tpm_sources)
#     target_sources(Tpm_CoreLib PRIVATE
#         "command/Asymmetric/EC_Ephemeral.c"
#         "command/Asymmetric/ECC_Decrypt.c"
#         )
# endfunction()

function(full_generate_tpm_sources)
    target_sources(Tpm_CoreLib PRIVATE
        "command/Asymmetric/EC_Ephemeral.c"
        "command/Asymmetric/ECC_Decrypt.c"
        "command/Asymmetric/ECC_Encrypt.c"
        "command/Asymmetric/ECC_Parameters.c"
        "command/Asymmetric/ECDH_KeyGen.c"
        "command/Asymmetric/ECDH_ZGen.c"
        "command/Asymmetric/RSA_Decrypt.c"
        "command/Asymmetric/RSA_Encrypt.c"
        "command/Asymmetric/ZGen_2Phase.c"
        "command/AttachedComponent/AC_GetCapability.c"
        "command/AttachedComponent/AC_Send.c"
        "command/AttachedComponent/AC_spt.c"
        "command/AttachedComponent/Policy_AC_SendSelect.c"
        "command/Attestation/Attest_spt.c"
        "command/Attestation/Certify.c"
        "command/Attestation/CertifyCreation.c"
        "command/Attestation/CertifyX509.c"
        "command/Attestation/GetCommandAuditDigest.c"
        "command/Attestation/GetSessionAuditDigest.c"
        "command/Attestation/GetTime.c"
        "command/Attestation/Quote.c"
        "command/Capability/GetCapability.c"
        "command/Capability/SetCapability.c"
        "command/Capability/TestParms.c"
        "command/ClockTimer/ACT_SetTimeout.c"
        "command/ClockTimer/ACT_spt.c"
        "command/ClockTimer/ClockRateAdjust.c"
        "command/ClockTimer/ClockSet.c"
        "command/ClockTimer/ReadClock.c"
        "command/CommandAudit/SetCommandCodeAuditStatus.c"
        "command/Context/Context_spt.c"
        "command/Context/ContextLoad.c"
        "command/Context/ContextSave.c"
        "command/Context/EvictControl.c"
        "command/Context/FlushContext.c"
        "command/DA/DictionaryAttackLockReset.c"
        "command/DA/DictionaryAttackParameters.c"
        "command/Duplication/Duplicate.c"
        "command/Duplication/Import.c"
        "command/Duplication/Rewrap.c"
        "command/EA/Policy_spt.c"
        "command/EA/PolicyAuthorize.c"
        "command/EA/PolicyAuthorizeNV.c"
        "command/EA/PolicyAuthValue.c"
        "command/EA/PolicyCapability.c"
        "command/EA/PolicyCommandCode.c"
        "command/EA/PolicyCounterTimer.c"
        "command/EA/PolicyCpHash.c"
        "command/EA/PolicyDuplicationSelect.c"
        "command/EA/PolicyGetDigest.c"
        "command/EA/PolicyLocality.c"
        "command/EA/PolicyNameHash.c"
        "command/EA/PolicyNV.c"
        "command/EA/PolicyNvWritten.c"
        "command/EA/PolicyOR.c"
        "command/EA/PolicyParameters.c"
        "command/EA/PolicyPassword.c"
        "command/EA/PolicyPCR.c"
        "command/EA/PolicyPhysicalPresence.c"
        "command/EA/PolicySecret.c"
        "command/EA/PolicySigned.c"
        "command/EA/PolicyTemplate.c"
        "command/EA/PolicyTicket.c"
        "command/EA/PolicyTransportSPDM.c"
        "command/Ecdaa/Commit.c"
        "command/FieldUpgrade/FieldUpgradeData.c"
        "command/FieldUpgrade/FieldUpgradeStart.c"
        "command/FieldUpgrade/FirmwareRead.c"
        "command/HashHMAC/EventSequenceComplete.c"
        "command/HashHMAC/HashSequenceStart.c"
        "command/HashHMAC/HMAC_Start.c"
        "command/HashHMAC/MAC_Start.c"
        "command/HashHMAC/SequenceComplete.c"
        "command/HashHMAC/SequenceUpdate.c"
        "command/Hierarchy/ChangeEPS.c"
        "command/Hierarchy/ChangePPS.c"
        "command/Hierarchy/Clear.c"
        "command/Hierarchy/ClearControl.c"
        "command/Hierarchy/CreatePrimary.c"
        "command/Hierarchy/HierarchyChangeAuth.c"
        "command/Hierarchy/HierarchyControl.c"
        "command/Hierarchy/ReadOnlyControl.c"
        "command/Hierarchy/SetPrimaryPolicy.c"
        "command/Misc/PP_Commands.c"
        "command/Misc/SetAlgorithmSet.c"
        "command/NVStorage/NV_Certify.c"
        "command/NVStorage/NV_ChangeAuth.c"
        "command/NVStorage/NV_DefineSpace.c"
        "command/NVStorage/NV_DefineSpace2.c"
        "command/NVStorage/NV_Extend.c"
        "command/NVStorage/NV_GlobalWriteLock.c"
        "command/NVStorage/NV_Increment.c"
        "command/NVStorage/NV_Read.c"
        "command/NVStorage/NV_ReadLock.c"
        "command/NVStorage/NV_ReadPublic.c"
        "command/NVStorage/NV_ReadPublic2.c"
        "command/NVStorage/NV_SetBits.c"
        "command/NVStorage/NV_spt.c"
        "command/NVStorage/NV_UndefineSpace.c"
        "command/NVStorage/NV_UndefineSpaceSpecial.c"
        "command/NVStorage/NV_Write.c"
        "command/NVStorage/NV_WriteLock.c"
        "command/Object/ActivateCredential.c"
        "command/Object/Create.c"
        "command/Object/CreateLoaded.c"
        "command/Object/Load.c"
        "command/Object/LoadExternal.c"
        "command/Object/MakeCredential.c"
        "command/Object/Object_spt.c"
        "command/Object/ObjectChangeAuth.c"
        "command/Object/ReadPublic.c"
        "command/Object/Unseal.c"
        "command/PCR/PCR_Allocate.c"
        "command/PCR/PCR_Event.c"
        "command/PCR/PCR_Extend.c"
        "command/PCR/PCR_Read.c"
        "command/PCR/PCR_Reset.c"
        "command/PCR/PCR_SetAuthPolicy.c"
        "command/PCR/PCR_SetAuthValue.c"
        "command/Random/GetRandom.c"
        "command/Random/StirRandom.c"
        "command/Session/PolicyRestart.c"
        "command/Session/StartAuthSession.c"
        "command/Signature/Sign.c"
        "command/Signature/VerifySignature.c"
        "command/Startup/Shutdown.c"
        "command/Startup/Startup.c"
        "command/Symmetric/EncryptDecrypt.c"
        "command/Symmetric/EncryptDecrypt_spt.c"
        "command/Symmetric/EncryptDecrypt2.c"
        "command/Symmetric/Hash.c"
        "command/Symmetric/HMAC.c"
        "command/Symmetric/MAC.c"
        "command/Testing/GetTestResult.c"
        "command/Testing/IncrementalSelfTest.c"
        "command/Testing/SelfTest.c"

        "crypt/AlgorithmTests.c"
        "crypt/CryptCmac.c"
        "crypt/CryptEccCrypt.c"
        "crypt/CryptEccData.c"
        "crypt/CryptEccKeyExchange.c"
        "crypt/CryptEccMain.c"
        "crypt/CryptEccSignature.c"
        "crypt/CryptHash.c"
        "crypt/CryptPrime.c"
        "crypt/CryptPrimeSieve.c"
        "crypt/CryptRand.c"
        "crypt/CryptRsa.c"
        "crypt/CryptSelfTest.c"
        "crypt/CryptSmac.c"
        "crypt/CryptSym.c"
        "crypt/CryptUtil.c"
        "crypt/PrimeData.c"
        "crypt/RsaKeyCache.c"
        "crypt/Ticket.c"

        "crypt/ecc/TpmEcc_Signature_ECDAA.c"
        "crypt/ecc/TpmEcc_Signature_ECDSA.c"
        "crypt/ecc/TpmEcc_Signature_Schnorr.c"
        "crypt/ecc/TpmEcc_Signature_SM2.c"
        "crypt/ecc/TpmEcc_Signature_Util.c"
        "crypt/ecc/TpmEcc_Util.c"

        "crypt/math/TpmMath_Debug.c"
        "crypt/math/TpmMath_Util.c"

        "events/_TPM_Hash_Data.c"
        "events/_TPM_Hash_End.c"
        "events/_TPM_Hash_Start.c"
        "events/_TPM_Init.c"
        "main/CommandDispatcher.c"
        "main/ExecCommand.c"
        "main/SessionProcess.c"
        "subsystem/CommandAudit.c"
        "subsystem/DA.c"
        "subsystem/Hierarchy.c"
        "subsystem/NvDynamic.c"
        "subsystem/NvReserved.c"
        "subsystem/Object.c"
        "subsystem/PCR.c"
        "subsystem/PP.c"
        "subsystem/Session.c"
        "subsystem/Time.c"
        "support/AlgorithmCap.c"
        "support/Bits.c"
        "support/CommandCodeAttributes.c"
        "support/Entity.c"
        "support/Global.c"
        "support/Handle.c"
        "support/IoBuffers.c"
        "support/Locality.c"
        "support/Manufacture.c"
        "support/Marshal.c"
        "support/MathOnByteBuffers.c"
        "support/Memory.c"
        "support/Power.c"
        "support/PropertyCap.c"
        "support/Response.c"
        "support/ResponseCodeProcessing.c"
        "support/SecChannel.c"
        "support/TableDrivenMarshal.c"
        "support/TableMarshalData.c"
        "support/TpmFail.c"
        "support/TpmSizeChecks.c"
        "X509/TpmASN1.c"
        "X509/X509_ECC.c"
        "X509/X509_RSA.c"
        "X509/X509_spt.c"
    )
endfunction()

#test_generate_tpm_sources()
full_generate_tpm_sources()

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################
# nothing to do, headers provided by other INTERFACE libraries

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
