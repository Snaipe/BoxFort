if (WIN32)
    find_program (HAS_SH sh.exe)
else ()
    find_program (HAS_SH sh)
endif ()

if (HAS_SH) # we disable the scripted tests when sh is not available
  add_custom_target(cram_tests)

  add_custom_command(TARGET cram_tests POST_BUILD
      COMMAND "${CMAKE_COMMAND}"
        -DPROJECT_BINARY_DIR="${PROJECT_BINARY_DIR}"
        -DCRAM_PATH="${CMAKE_CURRENT_SOURCE_DIR}/cram"
        -DENABLE_PATTERN_TESTS="${HAVE_PCRE}"
        -P "${CMAKE_MODULE_PATH}/Cram.cmake"
  )

  add_test(cram_tests cmake --build ${PROJECT_BINARY_DIR} --target cram_tests)
endif ()
