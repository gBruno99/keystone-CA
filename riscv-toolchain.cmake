if (NOT DEFINED ENV{RISCV})
  message(FATAL_ERROR "Please set RISCV environment variable to an installed RISCV path")
endif()
set(RISCV $ENV{RISCV})

set(CMAKE_SYSTEM_NAME       Generic)

set(CMAKE_C_COMPILER        riscv64-unknown-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER      riscv64-unknown-linux-gnu-g++)

set(CMAKE_FIND_ROOT_PATH    ${RISCV}/bin)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")
