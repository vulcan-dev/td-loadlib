cmake_minimum_required(VERSION 3.8)

set(PROJECT_NAME "teardown_hook")
project(${PROJECT_NAME})

set(CMAKE_C_STANDARD 99)
set(CMAKE_GENERATOR_PLATFORM x64)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

FILE(GLOB SRC_FILES
    "src/**.h"
    "src/**.c"
)

add_library(${PROJECT_NAME} SHARED ${SRC_FILES})

get_filename_component(ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_property(BUILD_MODE GLOBAL PROPERTY BUILD_MODE)

message("CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

if(EXISTS "${ROOT_DIR}/build/teardown_hook/${CMAKE_BUILD_TYPE}/teardown_hook.dll")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            "${ROOT_DIR}/build/teardown_hook/${CMAKE_BUILD_TYPE}/teardown_hook.dll"
            "${ROOT_DIR}/build/launcher/${CMAKE_BUILD_TYPE}/teardown_hook.dll"
    )
else()
    message(WARNING "teardown_hook.dll not found in ${ROOT_DIR}/build/teardown_hook/${CMAKE_BUILD_TYPE}/teardown_hook.dll")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    "src"
)