# Copyright (C) 2016 Franklin "Snaipe" Mathieu.
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the LICENSE file distributed with BoxFort.

cmake_minimum_required (VERSION 2.8)

project (BoxFort C)

include (CheckSymbolExists)
include (CheckLibraryExists)

set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Modules")
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MODULE_DIR})

set (I386 "^(i[3-7]|x)86$")
set (AMD64 "^(x86_|x86-|AMD|amd|x)64$")

if (CMAKE_GENERATOR_PLATFORM)
    set (_ARCH "${CMAKE_GENERATOR_PLATFORM}")
else ()
    set (_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif ()

set (CMAKE_C_FLAGS_DEFAULT "${CMAKE_C_FLAGS}")

set (BXF_MANGLING "none")

if (MSVC)
    if (NOT CMAKE_GENERATOR_PLATFORM)
        set (_ARCH "x86")
    endif ()

    enable_language (ASM_MASM)
    if (CMAKE_GENERATOR MATCHES "^.*Win64$" OR _ARCH MATCHES "${AMD64}")
        set (BXF_ARCH "x86_64")
        set (BXF_ABI "win")
        set (BXF_BITS 64)
        set (BXF_ARCH_x86_64 1)
    elseif (_ARCH MATCHES "${I386}")
        set (BXF_ARCH "i386")
        set (BXF_ABI "cdecl")
        set (BXF_BITS 32)
        set (BXF_ARCH_x86 1)
        set (BXF_MANGLING "leading-underscore")
        set (CMAKE_ASM_MASM_FLAGS "${CMAKE_ASM_MASM_FLAGS} /safeseh")
    else ()
        message (FATAL_ERROR "Architecture '${_ARCH}' is not supported.")
    endif ()
    set (ASM_EXTENSION ".asm")
else ()
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -pedantic -fvisibility=hidden")

    enable_language (ASM)
    if (_ARCH MATCHES "${I386}")
        set (BXF_ARCH "i386")
        set (BXF_ABI "cdecl")
        set (BXF_BITS 32)
        set (BXF_ARCH_x86 1)
    elseif (_ARCH MATCHES "${AMD64}")
        if (WIN32)
            set (BXF_ABI "win")
        else ()
            set (BXF_ABI "systemv")
        endif ()
        set (BXF_ARCH "x86_64")
        set (BXF_BITS 64)
        set (BXF_ARCH_x86_64 1)
    else ()
        message (FATAL_ERROR "Architecture '${_ARCH}' is not supported.")
    endif ()
    set (ASM_EXTENSION ".S")
endif ()

option (USE_QEMU "Use QEMU to run the tests" OFF)
option (BXF_ARENA_REOPEN_SHM "Reopen the arena shm in child processes (POSIX)" OFF)
option (BXF_ARENA_FILE_BACKED "Arena memory is file-backed (POSIX)" OFF)
option (BXF_STATIC_LIB "Build a static library" OFF)
option (BXF_SAMPLES "Build the library samples" ON)
option (BXF_TESTS "Build the library tests" ON)
option (BXF_FORK_RESILIENCE "Build with fork resilience" ON)

# Assume ELF on POSIX initially, override values when needed
set (BXF_EXE_FORMAT elf)
set (BXF_OS_FAMILY posix)

if (CMAKE_SYSTEM_NAME MATCHES "(Linux|(Free|Net|Open)?BSD|Solaris|SunOS)")
    add_definitions(-D_XOPEN_SOURCE=600 -D_GNU_SOURCE)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set (BXF_EXE_FORMAT mach-o)
    set (BXF_MANGLING "leading-underscore")

    # This is mandatory because OS X fails silently when mmap'ing an inherited
    # shm file descriptor
    set (BXF_ARENA_REOPEN_SHM 1)
    set (BXF_ARENA_FILE_BACKED 1)
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    set (BXF_EXE_FORMAT pe)
    set (BXF_OS_FAMILY windows)
    add_definitions (-D_CRT_SECURE_NO_WARNINGS)
    add_definitions (-DWIN32_LEAN_AND_MEAN)
    add_definitions (-D_WIN32_WINNT=0x600)
else ()
    message (FATAL_ERROR "Platform '${CMAKE_SYSTEM_NAME}' is not supported.")
endif ()

# Set BXF_EXE_FMT_{format} to 1

string (TOUPPER "${BXF_EXE_FORMAT}" _EXE_SUFFIX)
string (REGEX REPLACE "[^A-Z0-9_]" "_" _EXE_SUFFIX "${_EXE_SUFFIX}")
set ("BXF_EXE_FMT_${_EXE_SUFFIX}" 1)

function (bxf_check_type_exists _T _H _VAR)
  include (CheckCSourceCompiles)
  check_c_source_compiles ("
    #include <${_H}>
    typedef ${_T} checked_type;
    int main(void) { return 0; }
  " ${_VAR})
endfunction ()

list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)

if (BXF_EXE_FMT_ELF)
  check_symbol_exists(_r_debug link.h HAVE__R_DEBUG)
  check_symbol_exists(_DYNAMIC link.h HAVE__DYNAMIC)
endif ()

check_symbol_exists(PR_SET_PDEATHSIG sys/prctl.h HAVE_PR_SET_PDEATHSIG)
check_library_exists(rt shm_open "sys/mman.h" HAVE_SHM)
if (HAVE_SHM AND NOT HAVE_LIBRT)
  set (HAVE_LIBRT 1)
endif ()

check_library_exists(rt clock_gettime "time.h" HAVE_CLOCK_GETTIME_RT)
if (HAVE_CLOCK_GETTIME_RT AND NOT HAVE_LIBRT)
  set (HAVE_LIBRT 1)
endif ()

if (NOT HAVE_CLOCK_GETTIME_RT)
  check_symbol_exists(clock_gettime "time.h" HAVE_CLOCK_GETTIME)
else ()
  set (HAVE_CLOCK_GETTIME "${HAVE_CLOCK_GETTIME_RT}" CACHE INTERNAL "Have symbol clock_gettime")
endif ()

check_symbol_exists(CLOCK_MONOTONIC_RAW "time.h" HAVE_CLOCK_MONOTONIC_RAW)

check_symbol_exists(gettimeofday "sys/time.h" HAVE_GETTIMEOFDAY)

check_library_exists(pthread pthread_cond_timedwait_relative_np
  "pthread.h" HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE_NP)

check_library_exists(m trunc "math.h" HAVE_LIBM)

list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)

include_directories(include src ${CMAKE_CURRENT_BINARY_DIR}/src)
add_subdirectory (src)

if (BXF_STATIC_LIB)
  add_library (boxfort STATIC ${SOURCE_FILES})
else ()
  add_library (boxfort SHARED ${SOURCE_FILES})
endif ()

if (HAVE_LIBRT)
  target_link_libraries(boxfort rt)
endif ()

if (HAVE_LIBM)
  target_link_libraries(boxfort m)
endif ()

find_package(Threads REQUIRED)

if (THREADS_HAVE_PTHREAD_ARG)
  set_property(TARGET boxfort PROPERTY COMPILE_OPTIONS "-pthread")
  set_property(TARGET boxfort PROPERTY INTERFACE_COMPILE_OPTIONS "-pthread")
endif ()

if (CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(boxfort "${CMAKE_THREAD_LIBS_INIT}")
endif ()

foreach (F ${INTERFACE_FILES})
  get_filename_component(DEST "${F}" PATH)
  install(FILES "${F}" DESTINATION "${DEST}" ${install_flags})
endforeach ()

install(TARGETS boxfort
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

add_custom_target(boxfort_tests ALL)

function (add_boxfort_sample _NAME)
    add_dependencies (boxfort_tests ${_NAME})

    if (USE_QEMU)
        add_test (${_NAME} qemu-${BXF_ARCH} -L "${CMAKE_FIND_ROOT_PATH}" ${_NAME})
    else ()
        add_test (${_NAME} ${_NAME})
    endif ()
endfunction ()

function (add_boxfort_test _NAME)
    add_executable (${_NAME} EXCLUDE_FROM_ALL ${ARGN})

    if (NOT MSVC)
        foreach (ARG ${ARGN})
            set_source_files_properties (${ARG} PROPERTIES COMPILE_FLAGS -O0)
        endforeach ()
    endif ()

    target_link_libraries (${_NAME} boxfort)
    add_boxfort_sample(${_NAME})
endfunction ()

enable_testing ()
if (BXF_TESTS)
  add_subdirectory (test)
endif ()

if (BXF_SAMPLES)
  add_subdirectory (sample)
endif ()

