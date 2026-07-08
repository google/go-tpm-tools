project(Tpm_CryptoLib_Ossl_Headers VERSION 1.0)
print_project_info()
add_library(Tpm_CryptoLib_Math_Ossl_Headers INTERFACE)
add_library(Tpm_CryptoLib_Math_Ossl_Headers::Tpm_CryptoLib_Math_Ossl_Headers ALIAS Tpm_CryptoLib_Math_Ossl_Headers)
add_library(Tpm_CryptoLib_Symmetric_Ossl_Headers ALIAS Tpm_CryptoLib_Math_Ossl_Headers)
add_library(Tpm_CryptoLib_Hash_Ossl_Headers ALIAS Tpm_CryptoLib_Math_Ossl_Headers)

target_include_directories(Tpm_CryptoLib_Math_Ossl_Headers
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Ossl>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(Tpm_CryptoLib_Math_Ossl_Headers)

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/BnToOsslMath.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnToOsslMath_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmToOsslHash.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmToOsslSupport_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmToOsslSym.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Ossl
)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(Tpm_CryptoLib_Math_Ossl_Headers)
