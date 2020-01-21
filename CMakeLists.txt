cmake_minimum_required(VERSION 3.1)
project(ppcdisasm)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})

include_directories("${PROJECT_SOURCE_DIR}")

file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/*.cpp")

add_executable(ppcdisasm ${SOURCES})
install (TARGETS ppcdisasm DESTINATION ${EXECUTABLE_OUTPUT_PATH})
