cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(metainfo_extract)

file(GLOB DIR_LIB_SRCS "*.cpp" "*.hpp")
add_library(${PROJECT_NAME} STATIC ${DIR_LIB_SRCS})
