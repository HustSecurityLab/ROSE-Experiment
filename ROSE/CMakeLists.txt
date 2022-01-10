cmake_minimum_required(VERSION 3.13)
project(ROSE)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/include /usr/include)
link_directories(/usr/local/lib)
link_libraries(-lcrypto -lrelic -lssl -lpthread)


add_executable(ROSE main.cpp
        KUPRF.h
        KUPRF.cpp
        common.h
        common.cpp
        rose_server.h
        rose_server.cpp
        rose_client.h
        rose_client.cpp sse_benchmark.cpp sse_benchmark.h)