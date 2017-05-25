INC                       =  -I$(HOME)/boost_1_60_0 -I../../../../../libscapi/lib -I../../../../../libscapi/install/include -I../../../../../libscapi/lib/OTExtensionBristol -I../../../../../ -I../../
LIBS                      =  -L../../../../../libscapi/install/lib -L$(HOME)/boost_1_60_0/stage/lib
INCLUDE_ARCHIVES_START    = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_END      = -Wl,-no-whole-archive
LINKER_OPTIONS            = $(INCLUDE_ARCHIVES_START) $(LIBS) -lboost_log -lboost_system -lboost_thread -lboost_serialization  -lboost_filesystem -lOTExtension -lMaliciousOTExtension -lrt -lntl -lcrypto -lssl -lpthread -ldl -lgmp -lgmpxx ../../../../../libscapi/scapi.a ../../lib/MaliciousYao.a $(INCLUDE_ARCHIVES_END)
CXX                      = g++ -std=c++11 $(INC) -O3 -Wall -Wno-unused-function -maes

all: AppOnlineP1.out

AppOnlineP1.out:
	@echo "compiling!"
#	$(CXX) AppOnlineP1.cpp -o $@ $(LINKER_OPTIONS)
	g++ -std=c++11 $(INC) -maes AppOnlineP1.cpp -o $@ -L../../../../../libscapi/install/lib -L$(HOME)/boost_1_60_0/stage/lib -lcrypto -lssl -lgmp -ldl -lboost_thread -lboost_system ../../../../../libscapi/scapi.a ../../lib/MaliciousYao.a -lboost_serialization ../../../../../libscapi/scapi.a -lpthread -lboost_filesystem -lgmp -lntl -lMaliciousOTExtension -lblake2
clean:
	rm -f ./*.o
	rm -f ./*.out
