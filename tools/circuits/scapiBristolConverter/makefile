CXX               = g++
LINKER_OPTIONS    =  ../../../libscapi.a
CPP_OPTIONS       = --std=c++14 -O3 -Wall -Wno-unused-function -Wno-unused-variable -Wno-expansion-to-defined -Wno-ignored-attributes -no-pie
OBJS              = ScapiBristolConverter.o CircuitConverter.o

all: scapiBristolConverter

scapiBristolConverter: $(OBJS)
	$(CXX) $(CPP_OPTIONS) -o $@ $(OBJS) $(LINKER_OPTIONS)

%.o: /%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

clean:
	rm -f scapiBristolConverter
	rm -f ./*.o





