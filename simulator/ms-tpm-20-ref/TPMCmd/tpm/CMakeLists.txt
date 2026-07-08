####################################################
# TPM Crypto Library configuration
####################################################
#
# The TPM library depends on related libraries:
#
# First, a "Platform" library.  This library provides platform/hardware specific
# features, such as accessing random number hardware and external (e.g. flash)
# storage.
#
# Second, a set of "Crypto" libraries.  This set consists of multiple libraries, one for each
# rough segment of cryptography: Symmetric algorithms (e.g. AES), Hashing algorithms (e.g. SHA), and
# Big Number mathematics for support asymmetric cryptographic algorithms, (e.g. RSA/ECC)
#
# Each of these crypto libraries are selected by a different CMake parameter:
#
# CMake TPM Crypto configuration variables:
# * cryptoLib_Hash
# * cryptoLib_Symmetric
# * cryptoLib_BnMath
#
# Each has a corresponding #define in the 'C' code", that must be set to a directory name
# relative to the "cryptolibs" folder.  For example:
# * HASH_LIB=Ossl
# * SYM_LIB=Ossl
# * BN_MATH_LIB=Ossl
#
# Each must be represented by a CMake library that has already been
# declared/created via add_library, named as follows:
#   Tpm_CryptoLib_Hash_${cryptoLib_Hash}
#   Tpm_CryptoLib_Symmetric_${cryptoLib_Symmetric}
#   Tpm_CryptoLib_BnMath_${cryptoLib_BnMath}
#
# Also, each crypto library must provide headers with a given naming pattern.
#
# For example, cryptoLib_Hash=Ossl requires a header exist named thus:
#
# #include <Ossl/TpmToOsslHash.h> etc.
#           ^^^^      ^^^^       = value of *_LIB variable
#                         ^^^^   = Hardcoded based on the particular variable
#
# The BnMath library has slightly different naming convention, see the code.
#
# The expectation is these crypto libraries will be added to the Tpm_CoreLib environment
# by a top-level CMakeLists via add_subdirectory.

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.16.3)
project(TpmCoreLibTop VERSION 1.62.0 LANGUAGES C)
print_project_info()

# Set some compiler options for everything below
add_library(Tpm_CompilerOptions INTERFACE)
add_library(Tpm_CompilerOptions::Tpm_CompilerOptions ALIAS Tpm_CompilerOptions)
####################################################
# Compiler Options
####################################################

# enable minimal rebuild
target_compile_options(Tpm_CompilerOptions INTERFACE
    "$<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:GNU,Clang>>:>"
    "$<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:MSVC>>:/Gm->"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(Tpm_CompilerOptions)

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################
# nothing to do, headers provided by TpmBigNum_Headers

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(Tpm_CompilerOptions)


# this project builds the Tpm_Platform_Interface Library
add_subdirectory(include/platform_interface)
# this project builds the Tpm_CryptoLibs_TpmBigNum library
add_subdirectory(cryptolibs/TpmBigNum)
# this project builds the Tpm_CoreLib Library
add_subdirectory(src)

