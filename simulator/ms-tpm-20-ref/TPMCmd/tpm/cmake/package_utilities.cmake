# utilities for creating CMake packages that work correctly with find_package, export, and include
# while enforcing some practices like blocking in-source builds
#
# required to support CMake 3.16 on Ubuntu 20.04 LTS
set(_THIS_MODULE_BASE_DIR "${CMAKE_CURRENT_LIST_DIR}")

# Don't do in-source builds.
function(disallow_in_source_builds)
    if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
        message(FATAL_ERROR "In-source builds are not allowed. Specify a build folder with -B.")
    endif()
endfunction()

# Don't pollute other projects by installing to the global system.
function(ensure_cross_compile_prefix)
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install CACHE PATH "..." FORCE)
        message(WARNING "CMAKE_INSTALL_PREFIX was not specified and the default is unsafe for cross-compiling; reset to ${CMAKE_INSTALL_PREFIX}!")
    endif()
endfunction()

# declare install folders, and create the package config files for the current project to be used
# by downstream projects.
function(install_and_export_config_targets SomeProjectName)
    if (NOT CMAKE_INSTALL_INCLUDEDIR)
        message(FATAL_ERROR "install_and_export_config_targets expects GNUInstallDirs to have been setup.")
    endif()

    install(TARGETS ${SomeProjectName}
            EXPORT ${SomeProjectName}Targets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # prefer (CMake 3.17) set(CONFIG_TEMPLATE_FILE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/Package_Config.in.cmake")
    set(CONFIG_TEMPLATE_FILE "${_THIS_MODULE_BASE_DIR}/Package_Config.in.cmake")

    # generate files to be used by downstream packages
    include(CMakePackageConfigHelpers)

    # prefer (CMake 3.17) set_property(TARGET ${SomeProjectName} PROPERTY VERSION @PROJECT_VERSION@)
    set_property(TARGET ${SomeProjectName} PROPERTY INTERFACE_${SomeProjectName}_VERSION ${PROJECT_VERSION})
    set_property(TARGET ${SomeProjectName} PROPERTY INTERFACE_${SomeProjectName}_MAJOR_VERSION ${PROJECT_MAJOR_VERSION})
    set_property(TARGET ${SomeProjectName} APPEND PROPERTY COMPATIBLE_INTERFACE_STRING INTERFACE_${SomeProjectName}_MAJOR_VERSION)
    if (PACKAGE_PROJECT_NAME)
        message(FATAL_ERROR "Package_Project_Name is expected to be unset")
    endif()

    # pass in the SomeProjectName into the config template
    set(PACKAGE_PROJECT_NAME ${SomeProjectName})
    configure_package_config_file(${CONFIG_TEMPLATE_FILE}
        ${CMAKE_CURRENT_BINARY_DIR}/${SomeProjectName}Config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/${SomeProjectName}/cmake
        PATH_VARS CMAKE_INSTALL_INCLUDEDIR CMAKE_INSTALL_LIBDIR)

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/${SomeProjectName}ConfigVersion.cmake
        VERSION ${${SomeProjectName}_VERSION}
        COMPATIBILITY SameMajorVersion )

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${SomeProjectName}Config.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/${SomeProjectName}ConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/${SomeProjectName}/cmake )

    export(EXPORT ${SomeProjectName}Targets
        FILE "${CMAKE_CURRENT_BINARY_DIR}/${SomeProjectName}/${SomeProjectName}ExportedTargets.cmake"
        NAMESPACE ${SomeProjectName}::
    )
endfunction()

# export the Targets.cmake file for this project
function(export_targets_cmake_file SomeProjectName)
    install(EXPORT ${SomeProjectName}Targets
            FILE ${SomeProjectName}InstalledTargets.cmake
            NAMESPACE ${SomeProjectName}::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/${SomeProjectName}/cmake
    )
endfunction()