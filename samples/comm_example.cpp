#include <boost/thread/thread.hpp>
#include "../include/comm/TwoPartyComm.hpp"


void print_send_message(const string  &s, int i) {
	cout << "sending message number " << i << " message: " << s << endl;
}
void print_recv_message(const string &s, int i) {
	cout << "receievd message number " << i << " message: " << s << endl;
}

void send_messages(CommParty* commParty, string * messages, int start, int end) {
	for (int i = start; i < end; i++) {
		auto s = messages[i];
		print_send_message(s, i);
		commParty->write((const byte *)s.c_str(), s.size());
	}
}

void recv_messages(CommParty* commParty, string * messages, int start, int end, 
	byte * buffer, int expectedSize) {
	auto sizeRead = commParty->read(buffer, expectedSize);
	// the size of all strings is 2. Parse the message to get the original strings
	int j = 0;
	for (int i = start; i < end; i++, j++) {
		unsigned char* uc = buffer;
		auto s = string(reinterpret_cast<char const*>(buffer+j*2), 2);
		print_recv_message(s, i);
		messages[i] = s;
	}
}

/*
* Testing Communication 
*/
int main(int argc, char* argv[])
{
	try
	{
		if (argc != 4)
		{
			std::cerr << "Usage: chat_server <server port> <client ip> <client port>";
			return 1;
		}
		boost::asio::io_service io_service;

		SocketPartyData me(IpAdress::from_string("127.0.0.1"), atoi(argv[1]));
		SocketPartyData other(IpAdress::from_string(argv[2]), atoi(argv[3]));
		std::unique_ptr<CommPartyTCPSynced> commParty(new CommPartyTCPSynced(io_service, me, other));
		boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

		cout << "tring to connect to: " << argv[2] << " port: " << argv[3] << endl;
		commParty->join();
		string sendMessages[6] = { "s0", "s1", "s2", "s3", "s4", "s5" };
		string recvMessages[6];
		byte buffer[100];
		// send 3 message. get 3. send additional 2 get 2. send 1 get 1
		send_messages(commParty.get(), sendMessages, 0, 3);
		recv_messages(commParty.get(), recvMessages, 0, 3, buffer, 6);
		send_messages(commParty.get(), sendMessages, 3, 5);
		recv_messages(commParty.get(), recvMessages, 3, 5, buffer, 4);
		send_messages(commParty.get(), sendMessages, 5, 6);
		recv_messages(commParty.get(), recvMessages, 5, 6, buffer, 2);
		io_service.stop();
		t.join();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
