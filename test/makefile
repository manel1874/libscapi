PROGRAM= tests.exe

all:: $(PROGRAM)

$(PROGRAM): 
	g++ -std=c++11 -maes -mavx -I/usr/include/openssl  -I../../boost_1_60_0 -I../install/include -o tests.exe tests.cpp interactiveMidProtocolsTests.cpp ../scapi.a -ldl -lpthread -L../install/lib -L../../boost_1_60_0/stage/lib -lssl -lboost_system -lntl -lgmp -lblake2 -lcrypto

tests:: all
	$(Program)

clean::
	rm tests.exe



