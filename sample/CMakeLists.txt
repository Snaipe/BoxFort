if (NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_DEFAULT} -std=c99 -Wall -Wextra -pedantic")
endif ()

include_directories(../include)

set(SAMPLES
    nested.c
    callback.c
    timeout.c
)

add_custom_target(boxfort_samples)
add_dependencies(boxfort_tests boxfort_samples)

macro(add_samples DIR_ SAMPLES_)
    foreach(sample ${SAMPLES_})
        add_executable(${sample}.bin EXCLUDE_FROM_ALL ${sample})
        add_dependencies(boxfort_samples ${sample}.bin)
        target_link_libraries(${sample}.bin boxfort)
        add_test(${sample} ${sample}.bin)
    endforeach()
endmacro()

add_samples("${CMAKE_CURRENT_LIST_DIR}/test" "${SAMPLES}")
