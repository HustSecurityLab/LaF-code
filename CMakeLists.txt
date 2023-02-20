cmake_minimum_required(VERSION 3.16)
project(LaF)

if(LINUX)
set(CMAKE_C_COMPILER "/usr/local/bin/gcc")
set(CMAKE_CXX_COMPILER "/usr/local/bin/g++")
endif()

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-g")

set(CMAKE_CXX_STANDARD 14)

if (APPLE)
include_directories(/usr/local/opt/openssl@3/include /usr/local/include)
link_directories(/usr/local/opt/openssl@3/lib /usr/local/lib)
endif()

add_executable(LaFClient
        MuS.cpp
        MuS.h
        NewHope512cpa/api.h
        NewHope512cpa/cpapke.h
        NewHope512cpa/fips202.h
        NewHope512cpa/ntt.h
        NewHope512cpa/params.h
        NewHope512cpa/poly.h
        NewHope512cpa/reduce.h
        NewHope512cpa/rng.h
        NewHope512cpa/verify.h
        NewHope512cpa/kem.cpp
        NewHope512cpa/cpapke.cpp
        NewHope512cpa/fips202.cpp
        NewHope512cpa/ntt.cpp
        NewHope512cpa/poly.cpp
        NewHope512cpa/precomp.cpp
        NewHope512cpa/reduce.cpp
        NewHope512cpa/rng.cpp
        NewHope512cpa/verify.cpp
        LaFParticipant.cpp
        LaFParticipant.h
        LaFCommon.h
        LaFCommon.cpp
        RunLaFClient.cpp)

target_link_libraries(LaFClient ntl crypto pthread gmp)

add_executable(LaFServer
        MuS.cpp
        MuS.h
        NewHope512cpa/api.h
        NewHope512cpa/cpapke.h
        NewHope512cpa/fips202.h
        NewHope512cpa/ntt.h
        NewHope512cpa/params.h
        NewHope512cpa/poly.h
        NewHope512cpa/reduce.h
        NewHope512cpa/rng.h
        NewHope512cpa/verify.h
        NewHope512cpa/kem.cpp
        NewHope512cpa/cpapke.cpp
        NewHope512cpa/fips202.cpp
        NewHope512cpa/ntt.cpp
        NewHope512cpa/poly.cpp
        NewHope512cpa/precomp.cpp
        NewHope512cpa/reduce.cpp
        NewHope512cpa/rng.cpp
        NewHope512cpa/verify.cpp
        LaFServer.cpp
        LaFServer.h
        LaFCommon.h
        LaFCommon.cpp
        RunLaFServer.cpp)

target_link_libraries(LaFServer ntl crypto pthread gmp)

add_executable(TestKeyExchange
        NewHope512cpa/api.h
        NewHope512cpa/cpapke.h
        NewHope512cpa/fips202.h
        NewHope512cpa/ntt.h
        NewHope512cpa/params.h
        NewHope512cpa/poly.h
        NewHope512cpa/reduce.h
        NewHope512cpa/rng.h
        NewHope512cpa/verify.h
        NewHope512cpa/fips202.cpp
        NewHope512cpa/ntt.cpp
        NewHope512cpa/poly.cpp
        NewHope512cpa/precomp.cpp
        NewHope512cpa/reduce.cpp
        NewHope512cpa/rng.cpp
        NewHope512cpa/verify.cpp
        LaFCommon.h
        LaFCommon.cpp
        MuS.cpp
        MuS.h
        test_key_exchange.cpp)

target_link_libraries(TestKeyExchange ntl crypto pthread gmp)