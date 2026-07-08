project(Tpm_Platform_Interface VERSION 1.0)
print_project_info()
add_library(Tpm_Platform_Interface INTERFACE)
add_library(Tpm_Platform_Interface::Tpm_Platform_Interface ALIAS Tpm_Platform_Interface)
target_link_libraries(Tpm_Platform_Interface INTERFACE TpmConfiguration::TpmConfiguration)
target_link_libraries(Tpm_Platform_Interface INTERFACE Tpm_Public_Headers::Tpm_Public_Headers)

# publish current directory parent so references need to use <platform_interface>
# prefix.
target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Platform_Interface>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/platform_to_tpm_interface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_to_platform_interface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pcrstruct.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Platform_Interface/platform_interface)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/ExecCommand_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/Manufacture_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/platform_pcr_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/platform_init_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/platform_failure_mode_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/platform_virtual_nv_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/_TPM_Hash_Data_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/_TPM_Hash_End_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/_TPM_Hash_Start_fp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/_TPM_Init_fp.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Platform_Interface/platform_interface/prototypes)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
