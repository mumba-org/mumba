# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

BASE_VER=0
include common.mk

LIBDIR ?= /lib
PRELOADNAME = libminijailpreload.so
PRELOADPATH = "$(LIBDIR)/$(PRELOADNAME)"
CPPFLAGS += -DPRELOADPATH='$(PRELOADPATH)'

# We don't build static libs by default.
BUILD_STATIC_LIBS ?= no

# Defines the pivot root path used by the minimalistic-mountns profile.
DEFAULT_PIVOT_ROOT ?= /var/empty
CPPFLAGS += -DDEFAULT_PIVOT_ROOT='"$(DEFAULT_PIVOT_ROOT)"'

ifeq ($(USE_seccomp),no)
CPPFLAGS += -DUSE_SECCOMP_SOFTFAIL
endif

BLOCK_NOEXEC_CONF ?= no
ifeq ($(BLOCK_NOEXEC_CONF),yes)
CPPFLAGS += -DBLOCK_NOEXEC_CONF
endif

ENFORCE_ROOTFS_CONF ?= no
ifeq ($(ENFORCE_ROOTFS_CONF),yes)
CPPFLAGS += -DENFORCE_ROOTFS_CONF
endif

# Allow people to use -L and related flags.
ALLOW_DEBUG_LOGGING ?= yes
ifeq ($(ALLOW_DEBUG_LOGGING),yes)
CPPFLAGS += -DALLOW_DEBUG_LOGGING
ifeq ($(SECCOMP_DEFAULT_RET_LOG),yes)
CPPFLAGS += -DSECCOMP_DEFAULT_RET_LOG
endif
endif

ifeq ($(USE_ASAN),yes)
CPPFLAGS += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address -fno-omit-frame-pointer
USE_EXIT_ON_DIE = yes
endif

# Setting this flag can be useful for both AddressSanitizer builds and running
# fuzzing tools, which do not expect crashes on gracefully-handled malformed
# inputs.
ifeq ($(USE_EXIT_ON_DIE),yes)
CPPFLAGS += -DUSE_EXIT_ON_DIE
endif

# Setting this flag allows duplicate syscalls definitions for seccomp filters.
ifeq ($(ALLOW_DUPLICATE_SYSCALLS),yes)
CPPFLAGS += -DALLOW_DUPLICATE_SYSCALLS
endif

MJ_COMMON_FLAGS = -Wunused-parameter -Wextra -Wno-missing-field-initializers
CFLAGS += $(MJ_COMMON_FLAGS)
CXXFLAGS += $(MJ_COMMON_FLAGS)

# Dependencies that all gtest based unittests should have.
UNITTEST_LIBS := -lcap
UNITTEST_DEPS := testrunner.o test_util.o

USE_SYSTEM_GTEST ?= no
ifeq ($(USE_SYSTEM_GTEST),no)
GTEST_CXXFLAGS := -std=gnu++14
GTEST_LIBS := gtest.a
UNITTEST_DEPS += $(GTEST_LIBS)
else
GTEST_CXXFLAGS := $(shell gtest-config --cxxflags 2>/dev/null || \
  echo "-pthread")
GTEST_LIBS := $(shell gtest-config --libs 2>/dev/null || \
  echo "-lgtest -pthread -lpthread")
endif
UNITTEST_LIBS += $(GTEST_LIBS)

CORE_OBJECT_FILES := libminijail.o syscall_filter.o signal_handler.o \
		bpf.o util.o system.o syscall_wrapper.o \
		config_parser.o libconstants.gen.o libsyscalls.gen.o
UNITTEST_DEPS += $(CORE_OBJECT_FILES)

all: CC_BINARY(minijail0) CC_LIBRARY(libminijail.so) \
	CC_LIBRARY(libminijailpreload.so)

parse_seccomp_policy: CXX_BINARY(parse_seccomp_policy)
dump_constants: CXX_STATIC_BINARY(dump_constants)

tests: TEST(CXX_BINARY(libminijail_unittest)) \
	TEST(CXX_BINARY(minijail0_cli_unittest)) \
	TEST(CXX_BINARY(syscall_filter_unittest)) \
	TEST(CXX_BINARY(system_unittest)) \
	TEST(CXX_BINARY(util_unittest)) \
	TEST(CXX_BINARY(config_parser_unittest))

CC_BINARY(minijail0): LDLIBS += -lcap -ldl
CC_BINARY(minijail0): $(CORE_OBJECT_FILES) \
	elfparse.o minijail0.o minijail0_cli.o
clean: CLEAN(minijail0)


CC_LIBRARY(libminijail.so): LDLIBS += -lcap
CC_LIBRARY(libminijail.so): $(CORE_OBJECT_FILES)
clean: CLEAN(libminijail.so)

CC_STATIC_LIBRARY(libminijail.pic.a): $(CORE_OBJECT_FILES)
CC_STATIC_LIBRARY(libminijail.pie.a): $(CORE_OBJECT_FILES)
clean: CLEAN(libminijail.*.a)

ifeq ($(BUILD_STATIC_LIBS),yes)
all: CC_STATIC_LIBRARY(libminijail.pic.a) CC_STATIC_LIBRARY(libminijail.pie.a)
endif

CXX_BINARY(libminijail_unittest): CXXFLAGS += -Wno-write-strings \
						$(GTEST_CXXFLAGS)
CXX_BINARY(libminijail_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(libminijail_unittest): $(UNITTEST_DEPS) libminijail_unittest.o
clean: CLEAN(libminijail_unittest)

TEST(CXX_BINARY(libminijail_unittest)): CC_LIBRARY(libminijailpreload.so)


CC_LIBRARY(libminijailpreload.so): LDLIBS += -lcap -ldl
CC_LIBRARY(libminijailpreload.so): libminijailpreload.o $(CORE_OBJECT_FILES)
clean: CLEAN(libminijailpreload.so)


CXX_BINARY(minijail0_cli_unittest): CXXFLAGS += $(GTEST_CXXFLAGS)
CXX_BINARY(minijail0_cli_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(minijail0_cli_unittest): $(UNITTEST_DEPS) minijail0_cli_unittest.o \
		minijail0_cli.o elfparse.o
clean: CLEAN(minijail0_cli_unittest)


CXX_BINARY(config_parser_unittest): CXXFLAGS += $(GTEST_CXXFLAGS)
CXX_BINARY(config_parser_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(config_parser_unittest): $(UNITTEST_DEPS) config_parser_unittest.o
clean: CLEAN(config_parser_unittest)

CXX_BINARY(syscall_filter_unittest): CXXFLAGS += -Wno-write-strings \
						$(GTEST_CXXFLAGS)
CXX_BINARY(syscall_filter_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(syscall_filter_unittest): $(UNITTEST_DEPS) syscall_filter_unittest.o
clean: CLEAN(syscall_filter_unittest)


CXX_BINARY(system_unittest): CXXFLAGS += $(GTEST_CXXFLAGS)
CXX_BINARY(system_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(system_unittest): $(UNITTEST_DEPS) system_unittest.o
clean: CLEAN(system_unittest)


CXX_BINARY(util_unittest): CXXFLAGS += $(GTEST_CXXFLAGS)
CXX_BINARY(util_unittest): LDLIBS += $(UNITTEST_LIBS)
CXX_BINARY(util_unittest): $(UNITTEST_DEPS) util_unittest.o
clean: CLEAN(util_unittest)


CXX_BINARY(parse_seccomp_policy): parse_seccomp_policy.o syscall_filter.o \
		bpf.o util.o libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(parse_seccomp_policy)


# Compiling dump_constants as a static executable makes it easy to run under
# qemu-user, which in turn simplifies cross-compiling bpf policies.
CXX_STATIC_BINARY(dump_constants): dump_constants.o \
		libconstants.gen.o libsyscalls.gen.o
clean: CLEAN(dump_constants)


constants.json: CXX_STATIC_BINARY(dump_constants)
	./dump_constants > $@
clean: CLEANFILE(constants.json)


libsyscalls.gen.o: CPPFLAGS += -I$(SRC)

libsyscalls.gen.o.depends: libsyscalls.gen.c

# Only regenerate libsyscalls.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libsyscalls.gen.c: $(SRC)/libsyscalls.h $(SRC)/Makefile
	@/bin/echo -e "GEN		$(subst $(SRC)/,,$<) ->  $@"
	$(QUIET)CC="$(CC)" $(SRC)/gen_syscalls.sh "$@"
clean: CLEAN(libsyscalls.gen.c)

$(eval $(call add_object_rules,libsyscalls.gen.o,CC,c,CFLAGS))

libconstants.gen.o: CPPFLAGS += -I$(SRC)

libconstants.gen.o.depends: libconstants.gen.c

# Only regenerate libconstants.gen.c if the Makefile or header changes.
# NOTE! This will not detect if the file is not appropriate for the target.
libconstants.gen.c: $(SRC)/libconstants.h $(SRC)/Makefile
	@/bin/echo -e "GEN		$(subst $(SRC)/,,$<) ->  $@"
	$(QUIET)CC="$(CC)" $(SRC)/gen_constants.sh "$@"
clean: CLEAN(libconstants.gen.c)

$(eval $(call add_object_rules,libconstants.gen.o,CC,c,CFLAGS))


################################################################################
# Google Test

ifeq ($(USE_SYSTEM_GTEST),no)
# Points to the root of Google Test, relative to where this file is.
# Remember to tweak this if you move this file.
GTEST_DIR = googletest-release-1.11.0/googletest

# Flags passed to the preprocessor.
# Set Google Test's header directory as a system directory, such that
# the compiler doesn't generate warnings in Google Test headers.
CPPFLAGS += -isystem $(GTEST_DIR)/include

# Flags passed to the C++ compiler.
GTEST_CXXFLAGS += -pthread

# All Google Test headers.  Usually you shouldn't change this
# definition.
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
		$(GTEST_DIR)/include/gtest/internal/*.h

# House-keeping build targets.
clean: clean_gtest

clean_gtest:
	$(QUIET)rm -f gtest.a gtest_main.a *.o

# Builds gtest.a and gtest_main.a.

# Usually you shouldn't tweak such internal variables, indicated by a
# trailing _.
GTEST_SRCS_ = $(GTEST_DIR)/src/*.cc $(GTEST_DIR)/src/*.h $(GTEST_HEADERS)

# For simplicity and to avoid depending on Google Test's
# implementation details, the dependencies specified below are
# conservative and not optimized.  This is fine as Google Test
# compiles fast and for ordinary users its source rarely changes.
gtest-all.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) $(GTEST_CXXFLAGS) -c \
		$(GTEST_DIR)/src/gtest-all.cc -o $@

gtest_main.o : $(GTEST_SRCS_)
	$(CXX) $(CPPFLAGS) -I$(GTEST_DIR) $(CXXFLAGS) $(GTEST_CXXFLAGS) -c \
		$(GTEST_DIR)/src/gtest_main.cc -o $@

gtest.a : gtest-all.o
	$(AR) $(ARFLAGS) $@ $^

gtest_main.a : gtest-all.o gtest_main.o
	$(AR) $(ARFLAGS) $@ $^

endif
################################################################################
