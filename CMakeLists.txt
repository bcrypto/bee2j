cmake_minimum_required(VERSION 3.1)
project(BEE2J C)

if(WIN32 OR MINGW OR ${CMAKE_C_PLATFORM_ID} STREQUAL MinGW)
    add_link_options(-static -static-libgcc -static-libstdc++)
endif()

option(BUILD_CMD OFF)
option(BUILD_TESTS OFF)

add_subdirectory(bee2)