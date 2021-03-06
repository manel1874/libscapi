cmake_minimum_required(VERSION 3.5)
project(ScapiTests)

set(CMAKE_CXX_STANDARD 14)
if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES aarch64)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fPIC -march=armv8-a+crypto -flax-vector-conversions")
    INCLUDE_DIRECTORIES($ENV{HOME} ${SCAPI_BASE_DIR}/install/include $ENV{HOME}/OTExtensionBristol)

else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx -maes -msse4.1 -mpclmul -mbmi2 -O3")
    INCLUDE_DIRECTORIES($ENV{HOME} ${SCAPI_BASE_DIR}/install/include
        ${SCAPI_BASE_DIR}/lib/OTExtensionBristol $ENV{HOME}/libOTe $ENV{HOME}/libOTe/cryptoTools)
endif()

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib)

set(SOURCE_FILES tests.cpp interactiveMidProtocolsTests.cpp)

add_executable(ScapiTests ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(ScapiTests
        ${SCAPI_BASE_DIR}/libscapi.a
        ${SCAPI_BASE_DIR}/install/lib/libntl.a
        boost_system boost_thread
        pthread gmp dl crypto ssl z)