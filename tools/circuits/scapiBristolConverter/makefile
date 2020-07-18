CXX               = g++
LINKER_OPTIONS    =  ../../../libscapi.a
CPP_OPTIONS       = -std=c++14 -O3 -Wall -Wno-unused-function -Wno-unused-variable -Wno-expansion-to-defined -Wno-ignored-attributes -no-pie

scapiBristolConverter: ScapiBristolConverter.cpp CircuitConverter.cpp
	$(CXX) $(CPP_OPTIONS) -o scapiBristolConverter ScapiBristolConverter.cpp CircuitConverter.cpp -I.