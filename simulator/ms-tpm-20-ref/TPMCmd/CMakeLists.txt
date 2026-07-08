###################################################################################
# Summary
##########################################################
# Top-level CMakeLists file for building a TPM Application via CMake
#
# This file is an example, and is designed to be customized for a different
# application as detailed in comments below.
#
##########################################################
# Description
##########################################################
# The Platform library and Simulator examples in the repo support both
# add_directory (building the TPM library, Platform, and Simulator together), as
# well as building the library in a separate build domain where the Platform and
# Application (simulator) are built in subsequent build passes, perhaps by a
# different build environment.
#
# The default behavior of this script is to build the Platform and Simulator in
# the same CMake pass as the library.
#
# This behavior is controlled by the Tpm_BuildOption_LibOnly variable.  If this
# is set to a TRUE value, then this CMakeLists file will only build the
# TPM Core Library and the crypto support.
#
# The scripts\cmake_all.cmd and related cmake_env/gen/build.cmd scripts
# demonstrate how to preform a multi-phase build using CMake where the Platform
# library and TPM Application are built separately from the Core library and
# each other and are connected by find_package(CONFIG).
#
# Note: The Core Library does not currently support building the crypto support
# in a separate build pass from the Core due to cyclic header dependencies between
# the crypto components.
#
##########################################################
# Notation
##########################################################
# Sections of this CMakeFiles.txt file are marked DO NOT MODIFY
# these are intended to be copied into a customized script
# in the same relative location of the other parts of the
# script when a custom TPM application is being created with
# CMake.
# Customizable sections are similarly marked and can be
# replaced as indicated.

##########################################################
# PART 0 - SETUP
##########################################################
# DO NOT MODIFY - Validate Directory Structure
cmake_minimum_required(VERSION 3.16.3)
if (NOT TPM_CMAKE_CORE_FOLDER)
    set(TPM_CMAKE_CORE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/tpm)
endif()

if (NOT EXISTS "${TPM_CMAKE_CORE_FOLDER}")
    message(FATAL_ERROR "${TPM_CMAKE_CORE_FOLDER} does not exist" )
endif()
if (NOT EXISTS "${TPM_CMAKE_CORE_FOLDER}/cryptolibs/common")
    message(FATAL_ERROR "${TPM_CMAKE_CORE_FOLDER}/cryptolibs/common does not exist" )
endif()
if (NOT EXISTS "${TPM_CMAKE_CORE_FOLDER}/include/tpm_public")
    message(FATAL_ERROR "${TPM_CMAKE_CORE_FOLDER}/include/tpm_public does not exist" )
endif()
if (NOT EXISTS "${TPM_CMAKE_CORE_FOLDER}/include/private")
    message(FATAL_ERROR "${TPM_CMAKE_CORE_FOLDER}/include/private does not exist" )
endif()
if (NOT EXISTS "${TPM_CMAKE_CORE_FOLDER}/cmake")
    message(FATAL_ERROR "${TPM_CMAKE_CORE_FOLDER}/cmake does not exist" )
endif()

# Include Package macros expected by the
# Reference Code CMake system.
include(${CMAKE_CURRENT_SOURCE_DIR}/tpm/cmake/tpm_support.cmake)

# Create CACHE placeholders Crypto options for CMake-gui
# and for verification.
generate_tpm_crypto_options()
##########################################################

##########################################################
# CUSTOMIZABLE: Top-Level CMake project representing the
#               application
# recommend not removing the ensure call
project(TpmReferenceApplication)
ensure_cross_compile_prefix()
print_project_info()
##########################################################

##########################################################
# CUSTOMIZABLE: Set the list of AVAILABLE Crypto Libs that
#               can be chosen in CMake-gui. This is not
#               the active set, but does restrict what can
#               be used.
set(cryptoLibOptions_Symmetric Ossl CACHE STRING "List of available symmetric crypto implementations")
set(cryptoLibOptions_Hash Ossl CACHE STRING "List of available hash implementations")
set(cryptoLibOptions_BnMath Ossl CACHE STRING "List of available bignum math implementations")
##########################################################

##########################################################
# CUSTOMIZABLE: Set the Crypto Libs, or set the default.
#               The values here or from the command line
#               must be in the list of allowed values
#               above. Providing defaults here allows
#               opening this CMakeLists directly in
#               Visual Studio.
#               The folders represented must exist as subdirs
#               of <root>/cryptolibs/<dir> (custom), or
#               tpm/cryptolibs/<dir> (built-ins)
#               The match is CASE-SENSITIVE!
#
# NULL is the default cache value set by generate_tpm_crypto_options
# if nothing has been set from the command line, use defaults
if (cryptoLib_Symmetric STREQUAL "NULL")
    set(cryptoLib_Symmetric Ossl)
endif()
if (cryptoLib_Hash STREQUAL "NULL")
    set(cryptoLib_Hash Ossl)
endif()
if (cryptoLib_BnMath STREQUAL "NULL")
    set(cryptoLib_BnMath Ossl)
endif()
if (cryptoLib_Math STREQUAL "NULL")
    set(cryptoLib_Math TpmBigNum)
endif()
##########################################################

##########################################################
# PART 1 - CONFIGURATION
##########################################################
# CUSTOMIZABLE: Copy/paste the TpmConfiguration folder
#               and customize as indicated. Then, set the
#               user_TpmConfiguration_Dir cache variable
#               to point to the customized folder.
#
# WARNING: Project Name ** MUST ** be TpmConfiguration as this
# is referenced by multiple downstream components
verify_tpm_crypto_options()
set(user_TpmConfiguration_Dir "${CMAKE_CURRENT_LIST_DIR}/TpmConfiguration" CACHE PATH "Directory containing customized TPM configuration headers")
add_subdirectory(${user_TpmConfiguration_Dir} TpmConfiguration)
##########################################################

##########################################################
# PART 2 - Enable Full Build warnings.
##########################################################
# set it on TpmConfiguration so it flows down to other libraries.
set(MSVC_OPTIONS /WX /Wall)
# turn off alignment padding warnings.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4820)
# turn off Spectre warnings
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd5045)
# turn off no function prototype given: converting '()' to '(void)'
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4255)
# for some reason the built-in limits.h complains without this on MSVC.
# minimal repro https://stackoverflow.com/questions/66408981/iostream-and-define-stdc-want-secure-lib-0-results-in-error-c2039-sprin
set(MSVC_OPTIONS "${MSVC_OPTIONS}" -D__STDC_WANT_SECURE_LIB__=1)
# turn off unreachable code warnings.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4702)
# turn off C4668 - 'x' is not defined as a preprocessor macro, replacing with '0' for '#if/#elif'
# this is actually unsafe for the TPM code because this error can happen if there is a mismatch
# between the core library and the configuration provided by the consuming code.
# However, some build servers necessitate this because they use old Windows SDK headers.
# that don't build cleanly.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4668)
# turn off C4710 - function not inlined
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4710)
# Hash casts fail on MSVC.
set(MSVC_OPTIONS "${MSVC_OPTIONS}" /wd4191)

# debug includes
#set(MSVC_OPTIONS "${MSVC_OPTIONS}" /showIncludes)

# warnings as errors
set(GCC_OPTIONS -Werror)

target_compile_options(TpmConfiguration INTERFACE
    "$<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:GNU,Clang>>:${GCC_OPTIONS}>"
    "$<$<AND:$<CONFIG:Debug>,$<C_COMPILER_ID:MSVC>>:${MSVC_OPTIONS}>"
)

##########################################################

##########################################################
# PART 3 - Build Header Libraries
# Public headers are intended to be included by any consumers of the TPM - including
# platform implementations and apps
###################################################################################
# DO NOT MODIFY
# this project builds the Tpm_Public_Headers Library
add_subdirectory(tpm/include/tpm_public)
# this project builds the Tpm_CryptoLib_Common Library
add_subdirectory(tpm/cryptolibs/common)
##########################################################

##########################################################
# PART 4 - Setup Crypto Library prerequisites
##########################################################
# CUSTOMIZABLE: Setup prerequisites for crypto libraries
#               before process_tpm_crypto_options
#
if(WIN32)
    # This layout of the OsslInclude folder is based on the behavior of the current
    # VS solution.
    if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
        set( OSSL_INCLUDE_SUBDIR "/x64")
    elseif( CMAKE_SIZEOF_VOID_P EQUAL 4 )
        set( OSSL_INCLUDE_SUBDIR "")
    else()
        message(FATAL_ERROR "Unable to determine OpenSSL Architecture.")
    endif()
    set(OSSL_INCLUDE_SUBDIR ${CMAKE_SOURCE_DIR}/OsslInclude${OSSL_INCLUDE_SUBDIR})
else()
    # let system defaults locate it.
    unset(OSSL_INCLUDE_SUBDIR)
endif()

##########################################################

##########################################################
# PART 5 - Process Crypto Libraries
##########################################################
# DO NOT MODIFY
# This function scans the requested crypto options and
# looks for the appropriate directory and calls
# add_subdirectory on them if found.
# This step is customized indirectly via the
# cryptoLib_* variables set above.
process_tpm_crypto_options()
##########################################################

##########################################################
# DO NOT MODIFY: build the Core TPM library.
add_subdirectory(tpm)
##########################################################

##########################################################
# CUSTOMIZABLE: Add the subdirectories for the Platform
#               and target application, if any.
#               These lines may be omitted and the
#               tpm library created above may be
#               consumed in another build system manually.
#
if (NOT Tpm_BuildOption_LibOnly)
    add_subdirectory(Platform)
    add_subdirectory(Simulator)
endif()
##########################################################
