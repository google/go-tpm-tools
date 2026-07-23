##########################################################
# DO NOT MODIFY - TPM Configuration Library
##########################################################
# The contents of the source files may be modified to specify any valid
# desired configuraton.  However, the CMake library name "TpmConfiguration"
# is required by the CoreLib to reference this project.  Recommend making
# no changes in this file.
cmake_minimum_required(VERSION 3.16.3)

# set the project name and version
# Must be TpmConfiguration
project(TpmConfiguration VERSION 1.0)
print_project_info()

# use standard output directories.  Expected by package_utilities
include(GNUInstallDirs)

add_library(TpmConfiguration INTERFACE)
add_library(TpmConfiguration::TpmConfiguration ALIAS TpmConfiguration)

target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmBuildSwitches.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_CommandList.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_ErrorCodes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/TpmProfile_Misc.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/VendorCommandList.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandAttributeData_s_ccAttr.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandAttributeData_s_commandAttributes.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandDispatchData_CommandStructures.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandDispatchData_s_CommandDataArray.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/CommandDispatcher.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/HandleProcess.inl
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration/VendorCommands)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmConfiguration/VendorCommands/prototypes/Vendor_TCG_Test_fp.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmConfiguration/VendorCommands/prototypes)


# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})

add_subdirectory(TpmVendorCommandHandlers)
