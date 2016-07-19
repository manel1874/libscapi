INC               =  -I../../boost_1_60_0 -I../lib -I../install/include -I../lib/OTExtensionBristol 
LIBS              =  -L../install/lib -L../../boost_1_60_0/stage/lib
LINKER_OPTIONS    =  ../scapi.a ../install/lib/libOTExtensionBristol.a ../install/lib/libsimpleot.a $(LIBS) -lcrypto -ldl -lboost_log -lboost_system -lboost_thread -lpthread -lssl -lgmp -lOTExtension -lMaliciousOTExtension -lrt
CPP_OPTIONS       = -std=c++11 $(INC) -O3 -Wall -Wno-unused-function
OBJS              = simple_dlog.o simple_sha1.o CommitmentExample.o SigmaProtocolExample.o comm_example.o YaoParties.o App1.o MaliciousOTExample.o OTExtensionBristolExample.o
all:: 
	g++ -c Simple/simple_dlog.cpp $(CPP_OPTIONS) 
	g++ -c Simple/simple_sha1.cpp $(CPP_OPTIONS) 
	g++ -c SigmaProtocols/SigmaProtocolExample.cpp $(CPP_OPTIONS)
	g++ -c Commitment/CommitmentExample.cpp $(CPP_OPTIONS)
	g++ -c Comm/comm_example.cpp $(CPP_OPTIONS)
	g++ -c MaliciousOT/MaliciousOTExample.cpp $(CPP_OPTIONS) -maes -mpclmul
	g++ -c OTExtensionBristol/OTExtensionBristolExample.cpp $(CPP_OPTIONS) -Wextra -Wno-non-template-friend $(LIBOPT) $(OPTIM) -pthread -maes -mpclmul -msse4.1 -msse2 -I.
	g++ -c Yao/YaoParties.cpp $(CPP_OPTIONS) -maes -mpclmul
	g++ -c Yao/App1.cpp $(CPP_OPTIONS) -maes -mpclmul
	g++ examples_main.cpp -o libscapi_example.exe $(OBJS) $(CPP_OPTIONS) $(LINKER_OPTIONS)
clean::
	rm ./*.exe
	rm ./*.o



