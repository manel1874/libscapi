INC               =  -I../../boost_1_64_0 -I../lib -I../install/include -I../lib/OTExtensionBristol -I../build
CXX               = g++ -std=c++11 $(INC) -O3 -Wall -Wno-unused-function -Wno-unused-variable
LIBS              =  -L../install/lib -L../../boost_1_64_0/stage/lib
LINKER_OPTIONS    =  ../libscapi.a ../install/lib/libOTExtensionBristol.a ../install/lib/libsimpleot.a $(LIBS) -lcrypto -ldl -lboost_log -lboost_system -lboost_thread -lboost_serialization -lboost_filesystem -lpthread -lssl -lgmp -lOTExtension -lMaliciousOTExtension -lrt
CPP_OPTIONS       = -std=c++11 $(INC) -O3 -Wall -Wno-unused-function 
OBJS              = simple_dlog.o simple_sha1.o CommitmentExample.o OTExample.o SigmaProtocolExample.o comm_example.o YaoParties.o App1.o MaliciousOTExample.o SemiHonestOT.o OTExtensionBristolExample.o ospsi_main.o OSPSIParty.o OSPSIServer.o unity.o

all: libscapi_example

libscapi_example: $(OBJS)
	$(CXX) examples_main.cpp -o $@ $(OBJS) $(LINKER_OPTIONS)

%.o: Yao/%.cpp
	$(CXX) -c -maes -mpclmul $< -o $@

%.o: Simple/%.cpp
	$(CXX) -c $< -o $@

%.o: Commitment/%.cpp
	$(CXX) -c $< -o $@

%.o: OT/%.cpp
	$(CXX) -c -maes -mpclmul $< -o $@

%.o: MaliciousOT/%.cpp
	$(CXX) -c -maes -mpclmul $< -o $@

%.o: SemiHonestOT/%.cpp
	$(CXX) -c -maes -mpclmul $< -o $@
	
%.o: OTExtensionBristol/%.cpp
	$(CXX) -c -Wextra -Wno-non-template-friend -pthread -maes -mpclmul -msse4.1 -msse2 -I. $< -o $@

%.o: SigmaProtocols/%.cpp
	$(CXX) -c $< -o $@
	
%.o: Comm/%.cpp
	$(CXX) -c $< -o $@
    
%.o: PrivateSetIntersection/%.cpp
	$(CXX) -c $< -o $@    

clean:
	rm -f libscapi_example
	rm -f ./*.o





