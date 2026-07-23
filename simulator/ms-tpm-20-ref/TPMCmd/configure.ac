dnl WARNING: don't forget you need to install sudo apt-get install autoconf-archive
dnl it doesn't come with build-essential or automake
dnl If you don't you will see this:
dnl Setting up build
dnl configure.ac:44: error: possibly undefined macro: AC_SUBST
dnl If this token and others are legitimate, please use m4_pattern_allow.
dnl See the Autoconf documentation.
dnl configure.ac:55: error: possibly undefined macro: AS_IF
dnl configure.ac:59: error: possibly undefined macro: AC_MSG_ERROR
dnl configure:4617: error: possibly undefined macro: AC_MSG_WARN

# Autotools is not officially supported. This file is included in order to ease
# the transition to CMake for users, and will go away in the future.

AC_INIT([ms-tpm-20-ref],
        [0.1],
        [https://github.com/trustedcomputinggroup/tpm/issues],
        [],
        [https://github.com/trustedcomputinggroup/tpm])
AC_CONFIG_MACRO_DIR([.])
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_RANLIB
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_FILES([Makefile])
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

dnl By enabling this feature tpm simulator gets seeds derived from hardware parameters.
dnl It is enabled only for linux devices.
dnl Note that the seeds are not derived from secure hardware source.

AC_ARG_ENABLE(usedeviceid,
    AS_HELP_STRING([--enable-usedeviceid],
    [tpm simulator get seeds derived from hardware parameters. Seeds are not derived from secure hardware source.]))

PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
AS_IF([test "x$enable_usedeviceid" = "xyes"], [
    PKG_CHECK_MODULES([LIBUDEV], [libudev])
    [ADDITIONAL_LIBS="-ludev"]
])

AC_ARG_ENABLE([pthread],
    [AS_HELP_STRING([--disable-pthread], [Disable pthread support (tpm simulator will not be built, but only the libraries)])],
    [use_pthread=$enableval], [use_pthread=yes])
AS_IF([test "x$use_pthread" = "xyes"],
    [AX_PTHREAD([], [AC_MSG_ERROR([requires pthread])])],
    [AC_MSG_NOTICE([pthread support disabled])])
AM_CONDITIONAL([HAVE_PTHREAD], [test "x$use_pthread" = "xyes"])

AC_DEFINE([HASH_LIB], [Ossl], [Crypto lib for hash algorithms])
AC_DEFINE([SYM_LIB], [Ossl], [Crypto lib for symmetric encryption algorithms])
AC_DEFINE([MATH_LIB], [TpmBigNum], [Crypto lib for asymmetric operations])
AC_DEFINE([BN_MATH_LIB], [Ossl], [Math lib for tpmbignum operations])

ADD_COMPILER_FLAG([-std=gnu11])
ADD_COMPILER_FLAG([-Werror])
ADD_COMPILER_FLAG([-Wall])
ADD_COMPILER_FLAG([-Wformat-security])
ADD_COMPILER_FLAG([-fstack-protector-all])
ADD_COMPILER_FLAG([-fPIC])

# This is needed when compiling against OpenSSL 3.0, as the Ossl bindings use:
#  - EC_POINT_set_affine_coordinates_GFp / EC_POINTs_mul
#  - AES_set_encrypt_key / AES_encrypt
#  - Camellia_set_key / Camellia_encrypt
ADD_COMPILER_FLAG([-Wno-error=deprecated-declarations])

AS_IF([test "x$enable_usedeviceid" = "xyes"], [
    ADD_COMPILER_FLAG([-DNDEBUG])
    ADD_COMPILER_FLAG([-g])
    ADD_COMPILER_FLAG([-DUSE_PLATFORM_EPS])
    AC_SUBST(ADDITIONAL_LIBS)
])
ADD_LINK_FLAG([-Wl,--no-undefined])
ADD_LINK_FLAG([-Wl,-z,noexecstack])
ADD_LINK_FLAG([-Wl,-z,now])
ADD_LINK_FLAG([-Wl,-z,relro])

AC_OUTPUT
