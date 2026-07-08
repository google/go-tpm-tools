project(Tpm_CryptoLib_Common VERSION 1.0)
print_project_info()
add_library(Tpm_CryptoLib_Common INTERFACE)
add_library(Tpm_CryptoLib_Common::Tpm_CryptoLib_Common ALIAS Tpm_CryptoLib_Common)

target_link_libraries(Tpm_CryptoLib_Common INTERFACE Tpm_Public_Headers)

target_include_directories(${PROJECT_NAME}
    INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/Tpm_CryptoLib_Common>"
)

# create install and export information for downstream projects to use
install_and_export_config_targets(${PROJECT_NAME})

##############################################################
# BEGIN --- install the header files provided by this project.
##############################################################

install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/CryptoInterface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/EccConstantData.inl
        ${CMAKE_CURRENT_SOURCE_DIR}/include/MathLibraryInterface.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/MathLibraryInterfaceTypes.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/Tpm_CryptoLib_Common)

# LAST: create the targets.cmake file for this package
export_targets_cmake_file(${PROJECT_NAME})
