cmake_minimum_required(VERSION 3.4)
project(hdhr)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_LINKER_FLAGS -lpthread)

include_directories(libhdhomerun)

add_subdirectory(libhdhomerun)

set(SOURCE_FILES main.cpp)
add_executable(hdhr ${SOURCE_FILES})
target_link_libraries(hdhr hdhomerun)