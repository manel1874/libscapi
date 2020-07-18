all: runOT

runOT: runOT.cpp OTParties.cpp Postman.cpp
	g++ -o runOT runOT.cpp OTParties.cpp Postman.cpp -I/home/manel -I/home/manel/boost_1_71_0 -std=c++11 libscapi.a -lboost_system -L/home/manel/boost_1_71_0/stage/lib -lssl -lcrypto -lgmp -g -pthread -Wall -Werror
