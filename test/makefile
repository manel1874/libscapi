PROGRAM= tests.exe

all:: $(PROGRAM)

$(PROGRAM): 
	g++ -std=c++11 -I../../boost_1_60_0 -o tests.exe tests.cpp ../scapi.a -lcrypto -ldl -lpthread -L../../boost_1_60_0/stage/lib -lboost_system

tests:: all
	$(Program)

clean::
	rm tests.exe



