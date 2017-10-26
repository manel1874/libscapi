cmake_minimum_required(VERSION 2.8)
project(SemiHonetYao)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -maes -mpclmul -mbmi2 -flto")

SET (BOOST_ROOT $ENV{HOME}/boost_1_64_0/)
SET (BOOST_INCLUDEDIR $ENV{HOME}/boost_1_64_0/)
SET (BOOST_LIBRARYDIR $ENV{HOME}/boost_1_64_0/stage/lib)
find_package(Boost COMPONENTS system thread REQUIRED)

INCLUDE_DIRECTORIES( $ENV{HOME} ${BOOST_INCLUDEDIR}
        $ENV{HOME}/libscapi/lib/OTExtensionBristol $ENV{HOME}/libscapi/lib/)

set(SOURCE_FILES YaoParties.cpp)


link_directories($ENV{HOME}/libscapi/install/lib ${BOOST_LIBRARYDIR})


add_executable(SemiHonetYao ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(SemiHonetYao
        $ENV{HOME}/libscapi/libscapi.a gmp gmpxx
        OTExtensionBristol
        $ENV{HOME}/libscapi/install/lib/libsimpleot.a
        boost_system boost_thread pthread crypto dl ssl z)
