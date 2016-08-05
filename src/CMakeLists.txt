# Copyright (C) 2016 Franklin "Snaipe" Mathieu.
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the LICENSE file distributed with BoxFort.

set (ASM_FILES src/asm/trampoline-${BXF_ARCH}${ASM_EXTENSION})

set (SOURCE_FILES ${ASM_FILES}
    src/addr.c
    src/addr.h
    src/arena.c
    src/arena.h
    src/config.h
    src/context.c
    src/context.h
    src/exe.h
    src/exe-${BXF_EXE_FORMAT}.c
    src/exe-${BXF_EXE_FORMAT}.h
    src/sandbox-${BXF_OS_FAMILY}.c
    src/sandbox-${BXF_OS_FAMILY}.h
    src/sandbox.c
    src/sandbox.h
    src/timeout-${BXF_OS_FAMILY}.c
    src/timeout.h
    src/timestamp.c
    src/timestamp.h
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h"
)

set (SOURCE_FILES ${SOURCE_FILES} PARENT_SCOPE)
