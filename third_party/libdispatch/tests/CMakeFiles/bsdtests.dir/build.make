# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/fabiok/Downloads/cmake-3.10.0-Linux-x86_64/bin/cmake

# The command to remove a file.
RM = /home/fabiok/Downloads/cmake-3.10.0-Linux-x86_64/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /workspace/source/swift/swift-corelibs-libdispatch

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /workspace/source/swift/swift-corelibs-libdispatch

# Include any dependencies generated for this target.
include tests/CMakeFiles/bsdtests.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/bsdtests.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/bsdtests.dir/flags.make

tests/CMakeFiles/bsdtests.dir/bsdtests.c.o: tests/CMakeFiles/bsdtests.dir/flags.make
tests/CMakeFiles/bsdtests.dir/bsdtests.c.o: tests/bsdtests.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspace/source/swift/swift-corelibs-libdispatch/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/CMakeFiles/bsdtests.dir/bsdtests.c.o"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bsdtests.dir/bsdtests.c.o   -c /workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtests.c

tests/CMakeFiles/bsdtests.dir/bsdtests.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bsdtests.dir/bsdtests.c.i"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtests.c > CMakeFiles/bsdtests.dir/bsdtests.c.i

tests/CMakeFiles/bsdtests.dir/bsdtests.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bsdtests.dir/bsdtests.c.s"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /workspace/source/swift/swift-corelibs-libdispatch/tests/bsdtests.c -o CMakeFiles/bsdtests.dir/bsdtests.c.s

tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.requires:

.PHONY : tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.requires

tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.provides: tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.requires
	$(MAKE) -f tests/CMakeFiles/bsdtests.dir/build.make tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.provides.build
.PHONY : tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.provides

tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.provides.build: tests/CMakeFiles/bsdtests.dir/bsdtests.c.o


tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o: tests/CMakeFiles/bsdtests.dir/flags.make
tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o: tests/dispatch_test.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/workspace/source/swift/swift-corelibs-libdispatch/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bsdtests.dir/dispatch_test.c.o   -c /workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_test.c

tests/CMakeFiles/bsdtests.dir/dispatch_test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bsdtests.dir/dispatch_test.c.i"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_test.c > CMakeFiles/bsdtests.dir/dispatch_test.c.i

tests/CMakeFiles/bsdtests.dir/dispatch_test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bsdtests.dir/dispatch_test.c.s"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && /workspace/mutante/third_party/llvm-build/Release+Asserts/bin/clang --sysroot=/workspace/mutante/build/linux/debian_sid_amd64-sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /workspace/source/swift/swift-corelibs-libdispatch/tests/dispatch_test.c -o CMakeFiles/bsdtests.dir/dispatch_test.c.s

tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.requires:

.PHONY : tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.requires

tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.provides: tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.requires
	$(MAKE) -f tests/CMakeFiles/bsdtests.dir/build.make tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.provides.build
.PHONY : tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.provides

tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.provides.build: tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o


# Object files for target bsdtests
bsdtests_OBJECTS = \
"CMakeFiles/bsdtests.dir/bsdtests.c.o" \
"CMakeFiles/bsdtests.dir/dispatch_test.c.o"

# External object files for target bsdtests
bsdtests_EXTERNAL_OBJECTS =

tests/libbsdtests.a: tests/CMakeFiles/bsdtests.dir/bsdtests.c.o
tests/libbsdtests.a: tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o
tests/libbsdtests.a: tests/CMakeFiles/bsdtests.dir/build.make
tests/libbsdtests.a: tests/CMakeFiles/bsdtests.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/workspace/source/swift/swift-corelibs-libdispatch/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C static library libbsdtests.a"
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && $(CMAKE_COMMAND) -P CMakeFiles/bsdtests.dir/cmake_clean_target.cmake
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bsdtests.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/bsdtests.dir/build: tests/libbsdtests.a

.PHONY : tests/CMakeFiles/bsdtests.dir/build

tests/CMakeFiles/bsdtests.dir/requires: tests/CMakeFiles/bsdtests.dir/bsdtests.c.o.requires
tests/CMakeFiles/bsdtests.dir/requires: tests/CMakeFiles/bsdtests.dir/dispatch_test.c.o.requires

.PHONY : tests/CMakeFiles/bsdtests.dir/requires

tests/CMakeFiles/bsdtests.dir/clean:
	cd /workspace/source/swift/swift-corelibs-libdispatch/tests && $(CMAKE_COMMAND) -P CMakeFiles/bsdtests.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/bsdtests.dir/clean

tests/CMakeFiles/bsdtests.dir/depend:
	cd /workspace/source/swift/swift-corelibs-libdispatch && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch/tests /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch/tests /workspace/source/swift/swift-corelibs-libdispatch/tests/CMakeFiles/bsdtests.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/bsdtests.dir/depend

