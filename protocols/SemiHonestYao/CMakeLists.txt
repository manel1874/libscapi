cmake_minimum_required(VERSION 2.8)
project(SemiHonestYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++14 -maes -mavx -mpclmul -mbmi2 ")

SET (BOOST_ROOT $ENV{HOME}/boost_1_64_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_64_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_64_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)

INCLUDE_DIRECTORIES( $ENV{HOME} ${BOOST_INCLUDEDIR}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol
        $ENV{HOME}/libscapi/install/include $ENV{HOME}/libscapi/install/include/libOTe/cryptoTools/
        $ENV{HOME}/libscapi/install/include/libOTe)

set(SOURCE_FILES YaoParties.cpp App1.cpp)


link_directories($ENV{HOME}/libscapi/install/lib ${BOOST_LIBRARYDIR})


add_executable(SemiHonestYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonestYao
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        libjsoncpp.a OTExtensionBristol libsimpleot.a liblibOTe.a libcryptoTools.a libmiracl.a
        boost_system boost_thread boost_log pthread crypto dl ssl z rt stdc++fs)
