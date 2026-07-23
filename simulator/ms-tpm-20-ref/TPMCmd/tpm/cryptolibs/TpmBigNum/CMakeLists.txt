# This is the default TPM Reference "BigNumber" (Math) implementation.
# This depends on a lower level "BnMath" implementation from some crypto library
# This is the higher of two layers in the Asymmetric Crypto code path.
# The library at this layer uses the CMake library name Tpm_CryptoLib_Math_*
# This specific library further expects a layer below name Tpm_CryptoLib_BnMath_*

project(Tpm_CryptoLib_TpmBigNum VERSION 1.0)
print_project_info()
# generate Tpm_CryptoLib_TpmBigNum_Headers
add_subdirectory(include)

add_library(Tpm_CryptoLib_TpmBigNum STATIC)
add_library(Tpm_CryptoLib_TpmBigNum::Tpm_CryptoLib_TpmBigNum ALIAS Tpm_CryptoLib_TpmBigNum)

target_link_libraries(Tpm_CryptoLib_TpmBigNum PUBLIC Tpm_CompilerOptions)
target_link_libraries(Tpm_CryptoLib_TpmBigNum PUBLIC Tpm_CryptoLib_Common)
#target_link_libraries(Tpm_CryptoLib_TpmBigNum PRIVATE Tpm_Private_Headers)
target_link_libraries(Tpm_CryptoLib_TpmBigNum PUBLIC Tpm_CryptoLib_TpmBigNum_Headers)

target_link_libraries(Tpm_CryptoLib_TpmBigNum PUBLIC Tpm_CryptoLib_Math_${cryptoLib_BnMath})

# get access to the private TPM headers directly so they don't show up in the
# usage attributes.  Using an INTERFACE library (Tpm_Private_Headers) doesn't allow
# private inheritance
target_include_directories(Tpm_CryptoLib_TpmBigNum PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>"
)

target_include_directories(Tpm_CryptoLib_TpmBigNum
    PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/TpmBigNum>"
)

target_sources(Tpm_CryptoLib_TpmBigNum PRIVATE
    "BnConvert.c"
    "BnEccConstants.c"
    "BnMath.c"
    "BnMemory.c"
    "BnUtil.c"
    "TpmBigNumThunks.c"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################
# nothing to do, headers provided by TpmBigNum_Headers

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
