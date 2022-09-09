cmake_minimum_required(VERSION 3.8)

set(PROJECT_NAME "loadlib-global")
project(${PROJECT_NAME})

add_subdirectory(launcher)
add_subdirectory(teardown_hook)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT launcher)