CXX               = g++
CPP_OPTIONS       = --std=c++14 -O3 -Wall -Wno-unused-function -Wno-unused-variable -Wno-expansion-to-defined -Wno-ignored-attributes -no-pie
OBJS              = ScapiNecConverter.o Circuit.o CircuitConverter.o

all: scapiNecConverter

scapiNecConverter: $(OBJS)
	$(CXX) $(CPP_OPTIONS) -o $@ $(OBJS)

%.o: /%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

clean:
	rm -f scapiNecConverter
	rm -f ./*.o





