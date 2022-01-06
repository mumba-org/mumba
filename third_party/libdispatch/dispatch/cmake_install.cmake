# Install script for directory: /workspace/source/swift/swift-corelibs-libdispatch/dispatch

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/dispatch" TYPE FILE FILES
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/base.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/block.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/data.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/dispatch.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/group.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/introspection.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/io.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/object.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/once.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/queue.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/semaphore.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/source.h"
    "/workspace/source/swift/swift-corelibs-libdispatch/dispatch/time.h"
    )
endif()

