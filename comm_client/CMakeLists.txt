cmake_minimum_required(VERSION 2.8)
project(commclient)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++0x")

INCLUDE_DIRECTORIES(
)

set(SOURCE_FILES
	cct_proxy_client.cpp
	cct_proxy_service.cpp
	comm_client.cpp
	comm_client_tcp_mesh.cpp
)

add_library(commclient SHARED ${SOURCE_FILES})

target_link_libraries( commclient
	event
)
