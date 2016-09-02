# Copyright (C) 2016 Franklin "Snaipe" Mathieu.
# Redistribution and use of this file is allowed according to the terms of the MIT license.
# For details see the LICENSE file distributed with BoxFort.

include (CheckCSourceCompiles)

function (check_type_exists _T _H _VAR)
  check_c_source_compiles ("
    #include <${_H}>
    typedef ${_T} checked_type;
    int main(void) { return 0; }
  " ${_VAR})
endfunction ()

function (check_asm_source_compiles _S _VAR)
  if (NOT CMAKE_ASM-ATT_COMPILER_WORKS)
    set (${_VAR} FALSE)
    return ()
  endif ()

  set (SRC "${PROJECT_BINARY_DIR}/CMakeFiles/CheckASMSource.S")
  file (WRITE ${SRC} "
    ${_S}
    .globl main
    main:
  ")
  try_compile (${_VAR} "${PROJECT_BINARY_DIR}/CMakeFiles" ${SRC}
    OUTPUT_VARIABLE OUT)
  if (${_VAR})
    file (APPEND "${PROJECT_BINARY_DIR}/CMakeFiles/CMakeOutput.log" "${OUT}")
  else ()
    file (APPEND "${PROJECT_BINARY_DIR}/CMakeFiles/CMakeError.log" "${OUT}")
  endif ()
endfunction ()

function (check_asm_directive_exists _D _VAR)
  message ("-- Looking whether assembler supports `${_D}`")
  check_asm_source_compiles ("
    ${_D}
    test:
  " ${_VAR})
  if (${_VAR})
    message ("-- Looking whether assembler supports `${_D}` - found")
  else ()
    message ("-- Looking whether assembler supports `${_D}` - not found")
  endif ()
endfunction ()
