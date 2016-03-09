INC = -I../../../boost_1_60_0 -I../../lib -I../../install/include
LIB = -L../../install/lib -L../../../boost_1_60_0/stage/lib

all:: YaoParties.o
	sed -i'' 's/main.*(/main(/' App1.cpp
	#sudo cp /usr/ssl/lib/libcrypto.so.1.1.0 /usr/lib/
	g++ -std=c++11 -o App1.exe YaoParties.o App1.cpp ../../scapi.a -lcrypto -ldl $(INC) $(LIB) -lOTExtension -lScGarbledCircuit -lboost_log -lboost_system -lboost_thread -lpthread -maes -mpclmul

YaoParties.o : 
	g++ -c -std=c++11 $(INC)  -o YaoParties.o YaoParties.cpp -maes -mpclmul

tests:: all
	$(Program)

clean::
	rm YaoParties.o
	rm App1.exe



