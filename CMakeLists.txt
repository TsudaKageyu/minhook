#  DarkHook - The Minimalistic API Hooking Library for x64/x86
#  Copyright (C) 2009-2017 Tsuda Kageyu.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
#  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required(VERSION 3.20)

project(darkhook LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CMakePackageConfigHelpers)

set(DARKHOOK_MAJOR_VERSION 1)
set(DARKHOOK_MINOR_VERSION 3)
set(DARKHOOK_PATCH_VERSION 3)
set(DARKHOOK_VERSION ${DARKHOOK_MAJOR_VERSION}.${DARKHOOK_MINOR_VERSION}.${DARKHOOK_PATCH_VERSION})

################
#    BUILD     # 
################

option(BUILD_SHARED_LIBS "build shared version" OFF)

set(SOURCES_DARKHOOK 
  "src/buffer.cpp"
  "src/hook.cpp"
  "src/trampoline.cpp"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(SOURCES_HDE "src/hde/hde64.cpp")
else()
  set(SOURCES_HDE "src/hde/hde32.cpp")
endif()

if(BUILD_SHARED_LIBS)
  set(RESOURCES 
    "dll_resources/darkhook.rc"
    "dll_resources/darkhook.def"
  )
endif()

add_library(darkhook ${SOURCES_DARKHOOK} ${SOURCES_HDE} ${RESOURCES})

target_include_directories(darkhook PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
  $<INSTALL_INTERFACE:include>
)

target_include_directories(darkhook PRIVATE "src/")
target_include_directories(darkhook PRIVATE "src/hde/")

if(WIN32)
  set_target_properties(darkhook PROPERTIES PREFIX "")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)   
    set_target_properties(darkhook PROPERTIES DEBUG_POSTFIX ".x64d")
    set_target_properties(darkhook PROPERTIES RELEASE_POSTFIX ".x64")
    set_target_properties(darkhook PROPERTIES RELWITHDEBINFO_POSTFIX ".x64")
    set_target_properties(darkhook PROPERTIES MINSIZEREL_POSTFIX ".x64")
  else()
    set_target_properties(darkhook PROPERTIES DEBUG_POSTFIX ".x32d")
    set_target_properties(darkhook PROPERTIES RELEASE_POSTFIX ".x32")
    set_target_properties(darkhook PROPERTIES RELWITHDEBINFO_POSTFIX ".x32")
    set_target_properties(darkhook PROPERTIES MINSIZEREL_POSTFIX ".x32")
  endif()
else()
  set_target_properties(darkhook PROPERTIES PREFIX "lib")
  set_target_properties(darkhook PROPERTIES POSTFIX "")
  set_target_properties(darkhook PROPERTIES DEBUG_POSTFIX "d")
endif()

################
# CMAKE CONFIG # 
################

configure_package_config_file(
    "cmake/darkhook-config.cmake.in"
    "darkhook-config.cmake"
  INSTALL_DESTINATION 
    "share/darkhook"
)

write_basic_package_version_file(
  "darkhook-config-version.cmake"
VERSION 
  ${DARKHOOK_VERSION}
COMPATIBILITY
  AnyNewerVersion
)

install(
  FILES 
    "${CMAKE_CURRENT_BINARY_DIR}/darkhook-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/darkhook-config-version.cmake"
  DESTINATION 
    "share/darkhook"
)

###################
#     INSTALL     #
###################

install(TARGETS darkhook
        EXPORT darkhook-targets
        RUNTIME DESTINATION "bin"
        ARCHIVE DESTINATION "lib"
        LIBRARY DESTINATION "lib"
)

install(
  EXPORT
    darkhook-targets
  NAMESPACE 
    darkhook::
  DESTINATION 
    "share/darkhook"
)

install(
  DIRECTORY include DESTINATION .
)
