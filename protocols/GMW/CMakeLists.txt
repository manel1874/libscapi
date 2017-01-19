cmake_minimum_required(VERSION 2.8)
project(GMW)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -maes -mpclmul")

SET (BOOST_ROOT $ENV{HOME}/boost_1_60_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_60_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_60_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)

INCLUDE_DIRECTORIES($ENV{HOME} ${BOOST_INCLUDEDIR}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/lib/)

link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib ${BOOST_LIBRARYDIR})

set(SOURCE_FILES main.cpp GMWParty.h Circuit.cpp Circuit.h MPCCommunication.cpp MPCCommunication.h GMWParty.cpp)
add_executable(GMW ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(GMW $ENV{HOME}/libscapi/scapi.a gmp
        OTExtensionBristol
        $ENV{HOME}/libscapi/install/lib/libsimpleot.a
        boost_system boost_thread pthread crypto dl ssl z)
