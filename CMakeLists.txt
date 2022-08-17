cmake_minimum_required(VERSION 3.23)
project(communication_protocol C)

set(CMAKE_C_STANDARD 99)

add_executable(communication_protocol main.c)
target_link_libraries(communication_protocol wsock32 ws2_32)
