
if (HAS_WOLF)
    set_target_properties(tpm PROPERTIES HAS_WOLF YES)
    set_target_properties(tpm PROPERTIES HASH_LIB Wolf)
    set_target_properties(tpm PROPERTIES SYM_LIB Wolf)
    set_target_properties(tpm PROPERTIES MATH_LIB Wolf)

    add_library(tpm_wolf STATIC)

    # allow the tpm core and bignum implementation to get our headers
    target_link_libraries(TpmBigNum INTERFACE tpm_wolf)
    target_link_libraries(tpm INTERFACE tpm_wolf)

    target_compile_definitions(tpm PUBLIC
        HASH_LIB=Wolf
        SYM_LIB=Wolf
        MATH_LIB=TpmBigNum
        BN_MATH_LIB=Wolf
        WOLFSSL_USER_SETTINGS
        WOLFSSL_LIB
    )

    # This interface library also needs the big num implementation
    # from the reference code, public because tpm needs to inherit bignum as well
    target_link_libraries(tpm_wolf PUBLIC TpmBigNum)
    target_link_libraries(tpm_wolf PUBLIC tpm_cryptolib_includes)
    target_link_libraries(tpm_wolf PRIVATE tpm_protected_includes)
    target_link_libraries(tpm_wolf PRIVATE tpm)

    target_include_directories(tpm_wolf PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/../external/wolfssl/Debug;
        ${CMAKE_SOURCE_DIR}/../external/wolfssl;
    )

    #find_library(WolfLibrary wolfssl.lib PATHS  ${CMAKE_SOURCE_DIR}/../external/wolfssl/Debug;)
    #target_link_libraries(tpm INTERFACE ${WolfLibrary})
    message(VERBOSE "-- Selecting ${CMAKE_SOURCE_DIR}/../external/wolfssl include directories")

    target_link_options(tpm_wolf PUBLIC /LIBPATH:${CMAKE_SOURCE_DIR}/../external/internal_tpm_support/wolfssl/lib/x64)
    target_link_libraries(tpm INTERFACE wolfssl.lib)

    #target_link_directories(tpm_wolf PUBLIC ${CMAKE_SOURCE_DIR}/../external/wolfssl/Debug)

    target_sources(tpm_wolf PRIVATE
        "TpmToWolfDesSupport.c"
        "BnToWolfMath.c"
        "BnToWolfSupport.c"
    )

    # WOLFSSL_USER_SETTINGS;CYASSL_USER_SETTINGS
    # HAVE_AES_DECRYPT
    # HAVE_AES_ECB
    # WOLFSSL_AES_DIRECT
    # WOLFSSL_AES_COUNTER
    # HAVE_AESGCM
    # HAVE_AESCCM
    # WOLFSSL_AES_OFB
    # WOLFSSL_AES_CFB
    # WOLFSSL_AES_XTS
    # HAVE_AES_KEYWRAP
else()
    message(VERBOSE "No WolfSSL included.")
endif()
