# Copyright (C) 2016 Franklin "Snaipe" Mathieu.
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the LICENSE file distributed with BoxFort.

cmake_minimum_required (VERSION 2.8)

project (BoxFort C)

include (CheckSymbolExists)

set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.cmake/Modules")
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MODULE_DIR})

set (I386 "^(i[3-7]|x)86$")
set (AMD64 "^(x86_|x86-|AMD|amd|x)64$")

if (CMAKE_GENERATOR_PLATFORM)
    set (_ARCH "${CMAKE_GENERATOR_PLATFORM}")
else ()
    set (_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
endif ()

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
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -pedantic")

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

# Assume ELF on POSIX initially, override values when needed
set (BXF_EXE_FORMAT elf)
set (BXF_OS_FAMILY posix)

if (CMAKE_SYSTEM_NAME MATCHES "(Linux|(Free|Net|Open)?BSD|Solaris|SunOS)")
    add_definitions(-D_XOPEN_SOURCE=600 -D_GNU_SOURCE)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set (BXF_EXE_FORMAT mach-o)
    set (BXF_MANGLING "leading-underscore")
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    set (BXF_EXE_FORMAT pe)
    set (BXF_OS_FAMILY windows)
    add_definitions (-D_CRT_SECURE_NO_WARNINGS)
    add_definitions (-DWIN32_LEAN_AND_MEAN)
else ()
    message (FATAL_ERROR "Platform '${CMAKE_SYSTEM_NAME}' is not supported.")
endif ()

# Set BXF_EXE_FMT_{format} to 1

string (TOUPPER "${BXF_EXE_FORMAT}" _EXE_SUFFIX)
string (REGEX REPLACE "[^A-Z0-9_]" "_" _EXE_SUFFIX "${_EXE_SUFFIX}")
set ("BXF_EXE_FMT_${_EXE_SUFFIX}" 1)

function (mmk_check_type_exists _T _H _VAR)
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

  mmk_check_type_exists(Elf${BXF_BITS}_auxv_t elf.h HAVE_ELF_AUXV_T)
  mmk_check_type_exists(Elf${BXF_BITS}_Auxinfo elf.h HAVE_ELF_AUXINFO)
endif ()

check_symbol_exists(PR_SET_PDEATHSIG sys/prctl.h HAVE_PR_SET_PDEATHSIG)

list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)

include_directories(include src)
add_subdirectory (src)

add_library (boxfort SHARED ${SOURCE_FILES})

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
#add_subdirectory (test)
#add_subdirectory (sample)

