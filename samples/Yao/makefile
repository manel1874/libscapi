all:: YaoParties.o
	sed -i'' 's/main.*(/main(/' App1.cpp
	sudo cp /usr/ssl/lib/libcrypto.so.1.1.0 /usr/lib/
	g++ -std=c++11 -I../../../../../boost_1_60_0 -o App1.exe YaoParties.o App1.cpp ../../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lOTExtension -lScGarbledCircuit -lboost_log -lboost_system -lboost_thread -lpthread -maes -mpclmul

YaoParties.o : 
	g++ -c -std=c++11 -I../../../../../boost_1_60_0 -o YaoParties.o YaoParties.cpp -maes -mpclmul

tests:: all
	$(Program)

clean::
	rm YaoParties.o
	rm App1.exe



