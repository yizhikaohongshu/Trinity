cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(Trinity)
set(CMAKE_CXX_STANDARD 14)

add_subdirectory(packet_parse)
add_subdirectory(metainfo_extract)

file(GLOB DIR_SRCS "*.cpp")
add_executable(${PROJECT_NAME} "${DIR_SRCS}")

target_link_libraries(${PROJECT_NAME} gflags metainfo_extract packet_parse)