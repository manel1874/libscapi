
#project(frontend)


file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(frontend_libOTe  ${SRCS})

target_link_libraries(frontend_libOTe libOTe_Tests tests_cryptoTools boost_system boost_thread)