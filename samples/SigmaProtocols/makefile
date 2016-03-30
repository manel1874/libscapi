LIB = -L../../install/lib -L../../../boost_1_60_0/stage/lib
INC = -I../../../boost_1_60_0
all:: 
	g++ -std=c++11 -o SigmaProtocolExample.exe SigmaProtocolExample.cpp -DBOOST_LOG_DYN_LINK=1 ../../scapi.a $(INC) $(LIB) -lcrypto -ldl -lOTExtension -lScGarbledCircuit -lboost_log -lboost_system -lboost_thread -lpthread -maes -mpclmul -lgmp

clean::
	rm SigmaProtocolExample.exe
	rm SigmaProtocolExample.o



