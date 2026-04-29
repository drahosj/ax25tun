cmake_minimum_required(VERSION 3.16)
project(ax25tun)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(ax25tun 
    ax25tun.cpp
    arp.cpp
    kiss.cpp
    ax25.cpp
    util.cpp
)

target_compile_features(ax25tun PUBLIC cxx_std_23)

