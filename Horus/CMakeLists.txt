cmake_minimum_required(VERSION 3.13)
project(horus)

set(CMAKE_CXX_STANDARD 14)

link_libraries(-lcrypto)

include_directories(.)

add_executable(horus
        AES.cpp
        AES.hpp
        AVLTree.cpp
        AVLTree.h
        Bid.cpp
        Bid.h
        Horus.cpp
        Horus.h
        main.cpp
        OMAP.cpp
        OMAP.h
        ORAM.cpp
        ORAM.hpp
        PRFORAM.cpp
        PRFORAM.hpp
        RAMStore.cpp
        RAMStore.hpp
        Types.hpp
        Utilities.cpp
        Utilities.h
        utils.cpp
        sse_benchmark.cpp
        sse_benchmark.h)
