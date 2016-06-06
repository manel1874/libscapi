PROGRAM= tests.exe

all:: $(PROGRAM)

$(PROGRAM): 
	g++ -std=c++11 -I../../boost_1_60_0 -I../install/include -o tests.exe tests.cpp interactiveMidProtocolsTests.cpp ../scapi.a -lcrypto -ldl -lpthread -L../install/lib -L../../boost_1_60_0/stage/lib -lboost_system -lntl -lgmp -lcrypto -lssl

tests:: all
	$(Program)

clean::
	rm tests.exe



