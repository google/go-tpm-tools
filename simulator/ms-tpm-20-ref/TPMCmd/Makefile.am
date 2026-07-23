## Autotools is not officially supported. This file is included in order to ease
## the transition to CMake for users, and will go away in the future.

include src.mk

PLATFORM_INC = -I $(srcdir)/Platform/include \
    -I $(srcdir)/Platform/include/prototypes
SIMULATOR_INC =  -I $(srcdir)/Simulator/include \
    -I $(srcdir)/Simulator/include/prototypes
TPM_INC = \
    -I $(srcdir)/tpm/include \
    -I $(srcdir)/tpm/include/platform_interface \
    -I $(srcdir)/tpm/include/platform_interface/prototypes \
    -I $(srcdir)/tpm/include/private \
    -I $(srcdir)/tpm/include/private/prototypes \
    -I $(srcdir)/tpm/include/tpm_public \
    -I $(srcdir)/tpm/cryptolibs \
    -I $(srcdir)/tpm/cryptolibs/common/include \
    -I $(srcdir)/tpm/cryptolibs/Ossl/include \
    -I $(srcdir)/tpm/cryptolibs/TpmBigNum/include \
    -I $(srcdir)/TpmConfiguration

libplatform = Platform/src/libplatform.a
libtpm = tpm/src/libtpm.a
tpm2_simulator = Simulator/src/tpm2-simulator

noinst_LIBRARIES = $(libplatform) $(libtpm)

Platform_src_libplatform_a_CFLAGS = $(EXTRA_CFLAGS) $(PLATFORM_INC) $(TPM_INC)
Platform_src_libplatform_a_SOURCES = $(PLATFORM_C) $(PLATFORM_H) $(TPM_CONFIG_C)

if HAVE_PTHREAD
bin_PROGRAMS = $(tpm2_simulator)
Simulator_src_tpm2_simulator_CFLAGS = $(EXTRA_CFLAGS) $(PLATFORM_INC) \
    $(TPM_INC) $(SIMULATOR_INC) $(LIBCRYPTO_CFLAGS) $(PTHREAD_CFLAGS)
# the weird / duplicate static library is necessary for dealing with the
# circular dependency beetween libplatform and libtpm
Simulator_src_tpm2_simulator_LDADD = $(libplatform) $(libtpm) \
    $(libplatform) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) @ADDITIONAL_LIBS@
Simulator_src_tpm2_simulator_SOURCES = $(SIMULATOR_C) $(SIMULATOR_H)
endif

tpm_src_libtpm_a_CFLAGS = $(EXTRA_CFLAGS) $(PLATFORM_INC) $(TPM_INC) \
    $(LIBCRYPTO_CFLAGS)
tpm_src_libtpm_a_SOURCES = $(TPM_C) $(TPM_H) $(PLATFORM_H)
