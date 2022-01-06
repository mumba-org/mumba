# Install script for directory: /workspace/source/swift/swift-corelibs-libdispatch/man

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/share/man/man3/dispatch.3;/usr/local/share/man/man3/dispatch_after.3;/usr/local/share/man/man3/dispatch_api.3;/usr/local/share/man/man3/dispatch_apply.3;/usr/local/share/man/man3/dispatch_async.3;/usr/local/share/man/man3/dispatch_data_create.3;/usr/local/share/man/man3/dispatch_group_create.3;/usr/local/share/man/man3/dispatch_io_create.3;/usr/local/share/man/man3/dispatch_io_read.3;/usr/local/share/man/man3/dispatch_object.3;/usr/local/share/man/man3/dispatch_once.3;/usr/local/share/man/man3/dispatch_queue_create.3;/usr/local/share/man/man3/dispatch_read.3;/usr/local/share/man/man3/dispatch_semaphore_create.3;/usr/local/share/man/man3/dispatch_source_create.3;/usr/local/share/man/man3/dispatch_time.3")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/share/man/man3" TYPE FILE FILES
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_after.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_api.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_apply.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_async.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_data_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_group_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_io_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_io_read.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_object.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_once.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_queue_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_read.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_semaphore_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_source_create.3"
    "/workspace/source/swift/swift-corelibs-libdispatch/man/dispatch_time.3"
    )
endif()

