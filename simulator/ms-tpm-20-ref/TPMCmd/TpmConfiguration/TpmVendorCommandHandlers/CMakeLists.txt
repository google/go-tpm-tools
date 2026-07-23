##########################################################
# DO NOT MODIFY - TPM Configuration Library
##########################################################
# The contents of the source files may be modified to specify any valid
# desired configuraton.  However, the CMake library name "TpmVendorCommands"
# is required by the CoreLib to reference this project.  Recommend making
# no changes in this file.
cmake_minimum_required(VERSION 3.16.3)

if(NOT TARGET TpmConfiguration)
    message(FATAL_ERROR "TpmConfiguration TARGET must be declared before defining TpmVendorCommands_Handlers")
endif()

# set the project name and version
# Must be TpmVendorCommands
project(TpmVendorCommands_Handlers VERSION 1.0)
print_project_info()

# use standard output directories.  Expected by package_utilities
include(GNUInstallDirs)

add_library(TpmVendorCommands_Handlers STATIC)
add_library(TpmVendorCommands_Handlers::TpmVendorCommands_Handlers ALIAS TpmVendorCommands_Handlers)

target_link_libraries(TpmVendorCommands_Handlers PUBLIC TpmConfiguration)
target_link_libraries(TpmVendorCommands_Handlers PUBLIC Tpm_Public_Headers::Tpm_Public_Headers)
target_link_libraries(TpmVendorCommands_Handlers PUBLIC Tpm_CoreLib::Tpm_CoreLib)

# get access to the TPM headers directly so they don't show up in the
# usage attributes.  Using an INTERFACE library doesn't allow private inheritance
target_include_directories(TpmVendorCommands_Handlers PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../tpm/include>"
)


target_sources(TpmVendorCommands_Handlers PRIVATE
    Vendor_TCG_Test.c
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

# None
# install(FILES
#         ${CMAKE_CURRENT_SOURCE_DIR}/VendorCommandList.h
#         ${CMAKE_CURRENT_SOURCE_DIR}/CommandAttributeData_s_ccAttr.inl
#         ${CMAKE_CURRENT_SOURCE_DIR}/CommandAttributeData_s_commandAttributes.inl
#         ${CMAKE_CURRENT_SOURCE_DIR}/CommandAttributeData_CommandStructures.inl
#         ${CMAKE_CURRENT_SOURCE_DIR}/CommandAttributeData_s_CommandDataArray.inl
#         DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/TpmVendorCommands)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
