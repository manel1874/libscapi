cmake_minimum_required (VERSION 3.0)
project (emp-ot)
set(NAME "emp-ot")
set (CMAKE_CXX_STANDARD 11) 

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/common.cmake)
include(${CMAKE_FOLDER}/cmake/source_of_randomness.cmake)
include(${CMAKE_FOLDER}/cmake/threading.cmake)
#include_directories(${RELIC_INCLUDE_DIR} ${EMP-TOOL_INCLUDE_DIR})




find_package(emp-tool REQUIRED)
# Requirements for lattice
if (LATTICEOT)
  message(STATUS "Building with support for lattice OT")
  find_package(Eigen3 3.3 REQUIRED NO_MODULE)
  find_package(Boost REQUIRED COMPONENTS random)
  include_directories(${EMP-TOOL_INCLUDE_DIRS} ${EIGEN3_INCLUDE_DIR} ${Boost_INCLUDE_DIRS} ${RELIC_INCLUDE_DIR})
else (LATTICEOT)
  include_directories(${EMP-TOOL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS} ${RELIC_INCLUDE_DIR})
endif (LATTICEOT)

link_directories(${EMP-TOOL_LIBRARIES} ${RELIC_LIBRARY})


# Installation
install(FILES cmake/emp-ot-config.cmake DESTINATION cmake/)
install(DIRECTORY emp-ot DESTINATION include/)

# Test cases
macro (add_test _name)
  link_directories(${RELIC_LIBRARY})
  add_test_with_lib(${_name} ${EMP-TOOL_LIBRARIES})
  target_link_libraries("${_name}" librelic_s.a  ${OPENSSL_LIBRARIES} gmp ${EMP-TOOL_LIBRARIES})

  if (LATTICEOT AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${_name} PUBLIC -fext-numeric-literals)
  endif (LATTICEOT AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")

endmacro()

add_test(shot)
add_test(mot)
add_test(deltaot)
add_test(print_precomputation_table)
add_test(ideal)

if (LATTICEOT)
  set(INCLUDE_LATTICE_OT ON)
  add_test(lattice)
  target_link_libraries(lattice Eigen3::Eigen)
  SET_TARGET_PROPERTIES(lattice PROPERTIES COMPILE_DEFINITIONS "EMP_USE_RANDOM_DEVICE")
else(LATTICEOT)
  set(INCLUDE_LATTICE_OT OFF)

endif(LATTICEOT)

configure_file(${CMAKE_SOURCE_DIR}/emp-ot/latticeInclude.h.in ${CMAKE_SOURCE_DIR}/emp-ot/latticeInclude.h @ONLY)
