project(Tpm_Public_Headers VERSION 1.0)
print_project_info()
add_library(Tpm_Public_Headers INTERFACE)
# add the same alias a config package would create, allowing this to be used via
# add subdirectory.
add_library(Tpm_Public_Headers::Tpm_Public_Headers ALIAS Tpm_Public_Headers)
target_link_libraries(Tpm_Public_Headers INTERFACE TpmConfiguration)

# refer to .. in the build interface to cause include files to get the same
# directory view as the install interface where the public headers are
# under tpm_public.
target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Public_Headers>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/ACT.h
        ${CMAKE_CURRENT_SOURCE_DIR}/BaseTypes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/Capabilities.h
        ${CMAKE_CURRENT_SOURCE_DIR}/CompilerDependencies_gcc.h
        ${CMAKE_CURRENT_SOURCE_DIR}/CompilerDependencies_msvc.h
        ${CMAKE_CURRENT_SOURCE_DIR}/CompilerDependencies.h
        ${CMAKE_CURRENT_SOURCE_DIR}/endian_swap.h
        ${CMAKE_CURRENT_SOURCE_DIR}/GpMacros.h
        ${CMAKE_CURRENT_SOURCE_DIR}/MinMax.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_debug.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_public.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tpm_radix.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmAlgorithmDefines.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TPMB.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmCalculatedAttributes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/TpmTypes.h
        ${CMAKE_CURRENT_SOURCE_DIR}/VerifyConfiguration.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Public_Headers/tpm_public)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/prototypes/TpmFail_fp.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_Public_Headers/tpm_public/prototypes)
# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
