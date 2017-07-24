LIBS              =  -L../../install/lib -L../../../boost_1_60_0/stage/lib
LINKER_OPTIONS    =  ../../install/lib/libmiracl.a $(LIBS) 
   

#:cl /O2 /GX ake.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

all::
	g++ -std=c++11 -I../../install/include test.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp $(LINKER_OPTIONS)
