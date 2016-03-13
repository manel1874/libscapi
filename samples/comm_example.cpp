#include <boost/thread/thread.hpp>
#include "../include/comm/TwoPartyComm.hpp"
#include <thread>         // std::this_thread::sleep_for
#include <chrono>         // std::chrono::seconds

int main123(int argc, char* argv[])
{
	try
	{
		if (argc != 4)
		{
			std::cerr << "Usage: chat_server <server port> <client ip> <client port>";
			return 1;
		}

		Logger::configure_logging();
		boost::asio::io_service io_service;

		SocketPartyData me(IpAdress::from_string("127.0.0.1"), atoi(argv[1]));
		SocketPartyData other(IpAdress::from_string(argv[2]), atoi(argv[3]));
		auto server = make_shared<ChannelServer>(io_service, me, other);
		boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

		int i;
		cout << "please click 0 when ready" << endl;
		cin >> i;
		server->connect();
		this_thread::sleep_for(chrono::seconds(2));
		if (!server->is_connected())
		{
			cout << "sorry. connection failed" << endl;
			return -1;
		}
		else
		{
			cout << "connected. starting to send" << endl;
		}
			
		cin.clear();
		bool first = true;
		char line[Message::max_body_length + 1];
		vector<byte> * v;
		while (std::cin.getline(line, Message::max_body_length + 1))
		{
			if (!first)
			{
				using namespace std; // For strlen and memcpy.
				shared_ptr<byte> sLine((byte*)line);
				server->write(sLine, strlen(line));
				cout << "checking for recieved messages" << endl;
				while ((v = server->read_one()) != NULL)
				{
					cout << "GOT MESSAGE: " << string(v->begin(), v->end()) << endl; 
				}
			}
			else
				first = false;
		}


	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
