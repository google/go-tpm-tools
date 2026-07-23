include(${CMAKE_CURRENT_LIST_DIR}/package_utilities.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/misc_utilities.cmake)
disallow_in_source_builds()

set(default_cryptoLib_Dir "${CMAKE_CURRENT_LIST_DIR}/../cryptolibs")

function(generate_tpm_crypto_options)
    # Create cmake-gui variables that can be used to set the various crypto options.
    # the exact values here are expected to be provided by the calling script, except
    # TpmBigNum, which is currently the only supported Math option.
    # the other values are not set here, but are customized in the calling script.
    # must use PARENT_SCOPE since this is a function

    # https://cmake.org/pipermail/cmake/2016-October/064342.html
    #
    # option() is a handy shortcut for boolean options, but it's little more than
    # syntactic sugar for a cache variable of type BOOL. To create a tristate
    # variable, you can do this:
    #
    #   set(ENABLE_SOMETHING AUTO CACHE STRING "Enable SOMETHING support")  # create the variable
    #   set_property(CACHE ENABLE_SOMETHING PROPERTY STRINGS AUTO ON OFF)  # define list of values GUI will offer for the variable
    #
    # Then, you can test the variable like this:
    #
    #   if(ENABLE_SOMETHING STREQUAL "AUTO")
    #     # AUTO was used
    #   elseif(ENABLE_SOMETHING)
    #     # a true value (such as ON) was used
    #   else()
    #     # a false value (such as OFF) was used
    #   endif()

    # Regular cache variable which holds the path of the crypto libs. User can set this to their own
    # directory containing custom crypto implementations.
    set(user_cryptoLib_Dir "${default_cryptoLib_Dir}" CACHE PATH "Directory containing custom crypto implementations")

    # each of these tuples does 3 things:
    # 1. create a value in the cache (set to NULL) so we can attach a property to it (the option list)
    # 2. define the option list in a separate variable in parent scope so visible to related functions for processing selection results
    # 3. set the selection list as a property of the value in the cache.
    #set(cryptoLibOptions_Symmetric Ossl WOLF PARENT_SCOPE)
    set(cryptoLib_Symmetric NULL CACHE STRING "Choose Crypto Symmetric Library" )  # create the variable
    set_property(CACHE cryptoLib_Symmetric PROPERTY STRINGS ${cryptoLibOptions_Symmetric} )  # define list of values GUI will offer for the variable

    #set(cryptoLibOptions_Hash Ossl WOLF PARENT_SCOPE)
    set(cryptoLib_Hash      NULL CACHE STRING "Choose Crypto Hash Library" )  # create the variable
    set_property(CACHE cryptoLib_Hash PROPERTY STRINGS ${cryptoLibOptions_Hash})  # define list of values GUI will offer for the variable

    set(cryptoLibOptions_Math TpmBigNum PARENT_SCOPE)
    set(cryptoLib_Math NULL CACHE STRING "Choose Crypto Math Library" )  # create the variable
    set_property(CACHE cryptoLib_Math PROPERTY STRINGS ${cryptoLibOptions_Math})  # define list of values GUI will offer for the variable

    #set(cryptoLibOptions_BnMath Ossl WOLF PARENT_SCOPE)
    set(cryptoLib_BnMath    NULL CACHE STRING "Choose Crypto BnMath Library" )  # create the variable
    set_property(CACHE cryptoLib_BnMath PROPERTY STRINGS ${cryptoLibOptions_BnMath})  # define list of values GUI will offer for the variable

endfunction()

function(verify_tpm_crypto_options)
    # TPM Crypto Library Configuration
    if(NOT cryptoLib_Symmetric IN_LIST cryptoLibOptions_Symmetric)
        message(FATAL_ERROR "cryptoLib_Symmetric must be one of ${cryptoLibOptions_Symmetric}")
    else()
        message(NOTICE "Selected cryptoLib_Symmetric=${cryptoLib_Symmetric}")
    endif()

    if(NOT cryptoLib_Hash IN_LIST cryptoLibOptions_Hash)
        message(FATAL_ERROR "cryptoLib_Hash must be one of ${cryptoLibOptions_Hash}")
    else()
        message(NOTICE "Selected cryptoLib_Hash=${cryptoLib_Hash}")
    endif()

    if(NOT cryptoLib_Math IN_LIST cryptoLibOptions_Math)
        message(FATAL_ERROR "cryptoLib_Math (${cryptoLib_Math}) must be one of ${cryptoLibOptions_Math}")
    else()
        message(NOTICE "Selected cryptoLib_Math=${cryptoLib_Math}")
    endif()

    if(NOT cryptoLib_BnMath IN_LIST cryptoLibOptions_BnMath)
        message(FATAL_ERROR "cryptoLib_BnMath must be one of ${cryptoLibOptions_BnMath}")
    else()
        message(NOTICE "Selected cryptoLib_BnMath=${cryptoLib_BnMath}")
    endif()

endfunction()

function(process_tpm_crypto_options)
    # this function is expected to be called from the top-level CMakeLists.txt, and
    # the requested crypto libraries are expected to be provided by a cryptolibs
    # folder immediately below.
    # Otherwise, try to find a built-in version
    # Otherwise, fail
    set(default_crypto_dir ${CMAKE_CURRENT_SOURCE_DIR}/tpm/cryptolibs)

    target_compile_definitions(TpmConfiguration INTERFACE
        HASH_LIB=${cryptoLib_Hash}
        SYM_LIB=${cryptoLib_Symmetric}
        MATH_LIB=${cryptoLib_Math}
        BN_MATH_LIB=${cryptoLib_BnMath}
    )

    set(tpm_crypto_libset ${cryptoLib_Symmetric} ${cryptoLib_Hash} ${cryptoLib_BnMath}) # for use in this function
    list(REMOVE_DUPLICATES tpm_crypto_libset)
    set(tpm_crypto_libset ${tpm_crypto_libset} PARENT_SCOPE) # for use by other functions
    foreach(cryptodir ${tpm_crypto_libset})
        set(winner ${default_cryptoLib_Dir}/${cryptodir})
        set(winner_is_built_in TRUE)
        if(EXISTS "${user_cryptoLib_Dir}/${cryptodir}")
            set(winner "${user_cryptoLib_Dir}/${cryptodir}")
            set(winner_is_built_in FALSE)
        endif()

        if (NOT EXISTS "${winner}")
            message(FATAL_ERROR "Directory ${winner} referenced by crypto selections does not exist!")
        elseif (NOT EXISTS "${winner}/CMakeLists.txt")
            message(FATAL_ERROR "Directory ${winner} referenced by crypto selections does not contain CMakeLists.txt!")
        else()
            message(NOTICE "Providing Crypto Library [${cryptodir}] from directory [${winner}] referenced by crypto selections!")
        endif()

        if(winner_is_built_in)
            set(binary_dir "")
        else()
            set(binary_dir cryptolib_${cryptodir})
        endif()

        add_subdirectory(${winner} ${binary_dir})
    endforeach()
endfunction()

