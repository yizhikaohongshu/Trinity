cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(packet_parse)
set(CMAKE_CXX_STANDARD 14)

file(GLOB DIR_LIB_SRCS "*.cpp")
add_library (${PROJECT_NAME} ${DIR_LIB_SRCS})

target_link_libraries(${PROJECT_NAME} 
    libPcap++.a 
    libPacket++.a 
    libCommon++.a
)

target_link_libraries(${PROJECT_NAME}
    pcap
    pthread
)
