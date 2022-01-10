cmake_minimum_required(VERSION 3.13)
project(fides)

set(CMAKE_CXX_STANDARD 14)

include_directories(. /usr/local/include)
link_directories(/usr/local/lib)

link_libraries(-lcrypto -lssl -lgmp -lstdc++fs)

add_executable(fides
        fides.cpp
        fides.h
        main.cpp
        sophos.cpp
        sophos.h
        sse_benchmark.cpp
        sse_benchmark.h
        trapdoor_permutation.cpp
        trapdoor_permutation.h)
