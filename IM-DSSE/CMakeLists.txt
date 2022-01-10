cmake_minimum_required(VERSION 3.13)
project(IM-DSSE)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/include /usr/include)
link_directories(/usr/local/lib)
link_libraries(-ltomcrypt -laes_lin64 -lcrypto)

add_executable(IM-DSSE main.cpp
        config.h
        IM-DSSE-Client.h
        IM-DSSE-Client.cpp
        DSSE_Hashmap_Key_Class.h
        DSSE_Hashmap_Key_Class.cpp
        struct_MatrixType.h
        MasterKey.h
        MasterKey.cpp
        DSSE_KeyGen.h
        DSSE_KeyGen.cpp
        Krawczyk128_KDF.h
        Krawczyk128_KDF.cpp
        DSSE_Crypto.h
        DSSE_Crypto.cpp
        DSSE_Trapdoor.h
        DSSE_Trapdoor.cpp
        IM-DSSE-Server.h
        IM-DSSE-Server.cpp
        struct_thread_precompute_aeskey.h
        struct_thread_precompute_aeskey.cpp
        sse_benchmark.h
        sse_benchmark.cpp
        )