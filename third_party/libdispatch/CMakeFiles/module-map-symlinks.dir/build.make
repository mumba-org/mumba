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

# Utility rule file for module-map-symlinks.

# Include the progress variables for this target.
include CMakeFiles/module-map-symlinks.dir/progress.make

CMakeFiles/module-map-symlinks: dispatch/module.modulemap
CMakeFiles/module-map-symlinks: private/module.modulemap


dispatch/module.modulemap:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/workspace/source/swift/swift-corelibs-libdispatch/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating dispatch/module.modulemap, private/module.modulemap"
	/home/fabiok/Downloads/cmake-3.10.0-Linux-x86_64/bin/cmake -E create_symlink /workspace/source/swift/swift-corelibs-libdispatch/dispatch/generic/module.modulemap /workspace/source/swift/swift-corelibs-libdispatch/dispatch/module.modulemap
	/home/fabiok/Downloads/cmake-3.10.0-Linux-x86_64/bin/cmake -E create_symlink /workspace/source/swift/swift-corelibs-libdispatch/private/generic/module.modulemap /workspace/source/swift/swift-corelibs-libdispatch/private/module.modulemap

private/module.modulemap: dispatch/module.modulemap
	@$(CMAKE_COMMAND) -E touch_nocreate private/module.modulemap

module-map-symlinks: CMakeFiles/module-map-symlinks
module-map-symlinks: dispatch/module.modulemap
module-map-symlinks: private/module.modulemap
module-map-symlinks: CMakeFiles/module-map-symlinks.dir/build.make

.PHONY : module-map-symlinks

# Rule to build all files generated by this target.
CMakeFiles/module-map-symlinks.dir/build: module-map-symlinks

.PHONY : CMakeFiles/module-map-symlinks.dir/build

CMakeFiles/module-map-symlinks.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/module-map-symlinks.dir/cmake_clean.cmake
.PHONY : CMakeFiles/module-map-symlinks.dir/clean

CMakeFiles/module-map-symlinks.dir/depend:
	cd /workspace/source/swift/swift-corelibs-libdispatch && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch /workspace/source/swift/swift-corelibs-libdispatch/CMakeFiles/module-map-symlinks.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/module-map-symlinks.dir/depend

