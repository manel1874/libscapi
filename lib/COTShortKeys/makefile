all: test #lib

test: COTSK_Test.o COTSK.o
	g++ -g -o COTSK_Test COTSK_Test.o COTSK.o -L../../install/lib -L../.. -l:libOTExtensionBristol.a -l:libscapi.a -l:libsimpleot.a -l:libboost_system.a -l:libboost_thread.a -l:libssl.a -l:libcrypto.a -l:libntl.a -lpthread -lgmp -lm -ldl -lz 

COTSK_Test.o: COTSK_Test.cpp 
	g++ -c -std=c++11 -O3 -maes -mpclmul -msse4.1 -msse2 -Wall -Wno-reorder -fpic -I.. -I../OTExtensionBristol -I../../install/include  COTSK_Test.cpp

COTSK.o: COTSK.cpp COTSK_impl.h COTSK_Receiver_impl.h  COTSK_Sender_impl.h
	g++ -c -std=c++11 -O3 -maes -mpclmul -msse4.1 -msse2 -Wall -Wno-reorder -fpic -I.. -I../OTExtensionBristol -I../../install/include  COTSK.cpp

clean:
	rm *.o COTSK_Test 


