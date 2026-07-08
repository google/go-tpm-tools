cmake_minimum_required(VERSION 3.16.3)
include(${CMAKE_CURRENT_SOURCE_DIR}/../tpm/cmake/tpm_support.cmake)

project(Tpm_PlatformLib VERSION 1.0)
print_project_info()

# use standard output directories.  Expected by package_utilities
include(GNUInstallDirs)

add_library(Tpm_PlatformLib STATIC
    src/Cancel.c
    src/Clock.c
    src/DebugHelpers.c
    src/Entropy.c
    src/ExtraData.c
    src/Init.c
    src/Failure.c
    src/LocalityPlat.c
    src/NVMem.c
    src/NVVirtual.c
    src/PlatformACT.c
    src/PlatformData.c
    src/PlatformPcr.c
    src/PowerPlat.c
    src/PPPlat.c
    src/RunCommand.c
    src/SelfTest.c
    src/Unique.c
    src/VendorInfo.c
)
add_library(Tpm_PlatformLib::Tpm_PlatformLib ALIAS Tpm_PlatformLib)

target_include_directories(Tpm_PlatformLib PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/prototypes>"
)

# platform currently needs the private NV_*_fp headers
target_include_directories(${PROJECT_NAME} PRIVATE
     "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../tpm/include>"
)

# project public platform include dependencies
target_include_directories(Tpm_PlatformLib PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Tpm_PlatformLib/include>"
)

# Preprocessor definitions
target_compile_definitions(Tpm_PlatformLib PRIVATE
    _UNICODE
    WIN32
    _LIB
)

# Only call find_package if this CMakeLists file is not being included via
# add_subdirectory.  Calling find_package during add_subdirectory will cause the
# REQUIRED clause of the find_pacakge to fail since they haven't been built
# yet.)

if(PROJECT_IS_TOP_LEVEL)
    # Dependency libs and include directories published by Tpm_CoreLib
    find_package(TpmConfiguration CONFIG REQUIRED PATHS ${CMAKE_INSTALL_PREFIX} NO_DEFAULT_PATH )
    find_package(Tpm_Public_Headers CONFIG REQUIRED PATHS ${CMAKE_INSTALL_PREFIX} NO_DEFAULT_PATH )
    find_package(Tpm_Platform_Interface CONFIG REQUIRED PATHS ${CMAKE_INSTALL_PREFIX} NO_DEFAULT_PATH )
endif()

target_link_libraries(Tpm_PlatformLib PUBLIC TpmConfiguration::TpmConfiguration)
target_link_libraries(Tpm_PlatformLib PUBLIC Tpm_Public_Headers::Tpm_Public_Headers)
target_link_libraries(Tpm_PlatformLib PUBLIC Tpm_Platform_Interface::Tpm_Platform_Interface)

install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/Platform.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/PlatformACT.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/PlatformClock.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/PlatformData.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_PlatformLib/include)

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/prototypes/platform_public_interface.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_PlatformLib/include/prototypes)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
