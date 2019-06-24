INC               =  -I../install/include -I../lib/OTExtensionBristol -I../install/include/libOTe \
 -I../install/include/libOTe/cryptoTools
CXX               = g++ 
LIBS              =  ../install/lib
LINKER_OPTIONS    =  ../libscapi.a $(LIBS)/libOTExtensionBristol.a $(LIBS)/libOTe.a \
 $(LIBS)/libcryptoTools.a $(LIBS)/libmiracl.a $(LIBS)/libsimpleot.a \
  -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem \
 -lpthread -lgmp -lrt -lssl -lcrypto
CPP_OPTIONS       = --std=c++14 $(INC) -O3 -Wall -Wno-unused-function -Wno-unused-variable -Wno-expansion-to-defined -Wno-ignored-attributes -no-pie
OBJS              = simple_dlog.o simple_sha1.o simple_gmac.o CommitmentExample.o OTExample.o SigmaProtocolExample.o comm_example.o App1.o YaoParties.o OTExtensionBristolExample.o

all: libscapi_example

libscapi_example: $(OBJS)
	$(CXX) $(CPP_OPTIONS) examples_main.cpp -o $@ $(OBJS) $(LINKER_OPTIONS)

%.o: Simple/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

%.o: Commitment/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

%.o: OT/%.cpp
	$(CXX) $(CPP_OPTIONS) -c -maes -mpclmul $< -o $@

%.o: OTExtensionBristol/%.cpp
	$(CXX) $(CPP_OPTIONS) -c -Wextra -Wno-non-template-friend -pthread -maes -mpclmul -msse4.1 -msse2 -I. $< -o $@

%.o: SigmaProtocols/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@
	
%.o: Comm/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

%.o: Yao/%.cpp
	$(CXX) $(CPP_OPTIONS) -c $< -o $@

clean:
	rm -f libscapi_example
	rm -f ./*.o





