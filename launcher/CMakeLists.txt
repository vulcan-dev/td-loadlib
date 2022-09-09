cmake_minimum_required(VERSION 3.8)

set(PROJECT_NAME "launcher")
project(${PROJECT_NAME})

set(CMAKE_C_STANDARD 99)
set(CMAKE_GENERATOR_PLATFORM x64)

FILE(GLOB SRC_FILES
    "src/**.h"
    "src/**.c"
)

add_executable(${PROJECT_NAME} ${SRC_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC
    "src"
)