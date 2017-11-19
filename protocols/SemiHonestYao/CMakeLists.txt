cmake_minimum_required(VERSION 2.8)
project(SemiHonestYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -maes -mavx -mpclmul -mbmi2 ")


INCLUDE_DIRECTORIES( $ENV{HOME}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/install/include)

set(SOURCE_FILES YaoParties.cpp App1.cpp)


link_directories($ENV{HOME}/libscapi/install/lib)


add_executable(SemiHonestYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonestYao
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        libjsoncpp.a OTExtensionBristol libsimpleot.a
        boost_system boost_thread boost_log OTExtension MaliciousOTExtension pthread crypto dl ssl z rt stdc++fs)
