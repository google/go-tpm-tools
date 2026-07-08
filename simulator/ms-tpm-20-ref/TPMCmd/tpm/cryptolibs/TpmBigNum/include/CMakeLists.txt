project(Tpm_CryptoLib_TpmBigNum_Headers VERSION 1.0)
print_project_info()
add_library(Tpm_CryptoLib_TpmBigNum_Headers INTERFACE)
add_library(Tpm_CryptoLib_TpmBigNum_Headers::Tpm_CryptoLib_TpmBigNum_Headers ALIAS Tpm_CryptoLib_TpmBigNum_Headers)
target_link_libraries(Tpm_CryptoLib_TpmBigNum_Headers INTERFACE Tpm_CryptoLib_Common)
target_include_directories(Tpm_CryptoLib_TpmBigNum_Headers
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/TpmBigNum>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmBigNum/TpmToTpmBigNumMath.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnConvert_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnMath_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnMemory_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnSupport_Interface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnUtil_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BnValues.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmBigNum
)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
