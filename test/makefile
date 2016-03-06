PROGRAM= tests.exe

all:: $(PROGRAM)

$(PROGRAM): 
	g++ -std=c++11 -I../../../../boost_1_60_0 -o tests.exe tests.cpp ../ScapiCpp/scapi.a -lcrypto -ldl -lpthread -lboost_system -lboost_log

tests:: all
	$(Program)

clean::
	rm tests.exe



