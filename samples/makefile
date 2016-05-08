INC               =  -I../../boost_1_60_0 -I../lib -I../install/include
LIBS              =  -L../install/lib -L../../boost_1_60_0/stage/lib
LINKER_OPTIONS    =  ../scapi.a $(LIBS) -lcrypto -ldl -lboost_log -lboost_system -lboost_thread -lpthread -lssl -lgmp -lOTExtension
CPP_OPTIONS       = -std=c++11 $(INC)
OBJS              = simple_dlog.o simple_sha1.o SigmaProtocolExample.o comm_example.o YaoParties.o App1.o
all:: 
	g++ -c Simple/simple_dlog.cpp $(CPP_OPTIONS) 
	g++ -c Simple/simple_sha1.cpp $(CPP_OPTIONS) 
	g++ -c SigmaProtocols/SigmaProtocolExample.cpp $(CPP_OPTIONS)
	g++ -c Comm/comm_example.cpp $(CPP_OPTIONS)
	g++ -c Yao/YaoParties.cpp $(CPP_OPTIONS) -maes -mpclmul
	g++ -c Yao/App1.cpp $(CPP_OPTIONS) -maes -mpclmul
	g++ examples_main.cpp -o libscapi_example.exe $(OBJS) $(CPP_OPTIONS) $(LINKER_OPTIONS)
clean::
	rm ./*.exe
	rm ./*.o



