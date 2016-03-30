INC            = -I../../boost_1_60_0
CPP_OPTIONS   := -std=c++11 $(INC)  ../scapi.a -lcrypto -ldl -L../../boost_1_60_0/stage/lib/ -lboost_log -lboost_system -lboost_thread -lpthread
all:: 
	sed -i'' 's/main.*(/main(/' comm_example.cpp
	g++ -std=c++11 -I../../boost_1_60_0 -o comm_example.exe comm_example.cpp ../scapi.a -L../../boost_1_60_0/stage/lib -lcrypto -ldl -lboost_log -lboost_system -lboost_thread -lpthread
	sed -i'' 's/main.*(/main(/' simple_dlog.cpp
	g++ -std=c++11 -I../../boost_1_60_0 -o simple_dlog.exe simple_dlog.cpp ../scapi.a -L../../boost_1_60_0/stage/lib -lcrypto -ldl -lpthread -lboost_system -lboost_log -lgmp
	sed -i'' 's/main.*(/main(/'  simple_sha1.cpp
	g++ -std=c++11 -I../../boost_1_60_0 -o  simple_sha1.exe  simple_sha1.cpp ../scapi.a -L../../boost_1_60_0/stage/lib -lcrypto -ldl -lpthread -lboost_system -lboost_log -lgmp


tests:: all
	$(Program)

clean::
	rm ./*.exe



