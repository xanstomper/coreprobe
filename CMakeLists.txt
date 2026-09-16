cmake_minimum_required(VERSION 3.16)
project(osleuth_core CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(osleuth_core
  core/main.cpp
  core/core.cpp
)
target_include_directories(osleuth_core PRIVATE core)
target_compile_options(osleuth_core PRIVATE -Wall -Wextra -O2)
install(TARGETS osleuth_core RUNTIME DESTINATION bin)