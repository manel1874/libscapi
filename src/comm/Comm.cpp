#include "../../include/comm/Comm.hpp"


/*****************************************/
/* SocketPartyData						 */
/*****************************************/
int SocketPartyData::compare(const SocketPartyData &other) const {
	string thisString = ipAddress.to_string() + ":" + to_string(port);
	string otherString = other.ipAddress.to_string() + ":" + to_string(other.port);
	return thisString.compare(otherString);
}

/*****************************************/
/* CommParty			                */
/*****************************************/

void CommParty::writeWithSize(const byte* data, int size) {
	write((const byte *)&size, sizeof(int));
	write(data, size);
}

int CommParty::readSize() {
	byte buf[sizeof(int)];
	read(buf, sizeof(int));
	int * res = (int *)buf;
	return *res;
}

size_t CommParty::readWithSizeIntoVector(vector<byte> & targetVector) {
	int msgSize = readSize();
	targetVector.resize(msgSize);
	auto res = read((byte*)&targetVector[0], msgSize);
	return res;
}

/*****************************************/
/* CommPartyTCPSynced                    */
/*****************************************/

void CommPartyTCPSynced::join(int sleepBetweenAttempts, int timeout) {
	int     totalSleep = 0;
	bool    isAccepted  = false;
	bool    isConnected = false;
	// establish connections
	while (!isConnected || !isAccepted) {
		try {
			if (!isConnected) {
				tcp::resolver resolver(ioServiceClient);
				tcp::resolver::query query(other.getIpAddress().to_string(), to_string(other.getPort()));
				tcp::resolver::iterator endpointIterator = resolver.resolve(query);
				boost::asio::connect(clientSocket, endpointIterator);
				isConnected = true;
			}
		}
		catch (const boost::system::system_error& ex)
		{
			if (totalSleep > timeout)
			{
				cerr << "Failed to connect after timeout, aborting!";
				throw ex;
			}
			cout << "Failed to connect. sleeping for " << sleepBetweenAttempts <<
				" milliseconds, " << ex.what() << endl;
			this_thread::sleep_for(chrono::milliseconds(sleepBetweenAttempts));
			totalSleep += sleepBetweenAttempts;
		}
		if (!isAccepted) {
			boost::system::error_code ec;
			acceptor_.accept(serverSocket, ec);
			isAccepted = true;
		}
	}
	setSocketOptions();
}

void CommPartyTCPSynced::setSocketOptions() {
	boost::asio::ip::tcp::no_delay option(true);
	serverSocket.set_option(option);
	clientSocket.set_option(option);
}

void CommPartyTCPSynced::write(const byte* data, int size) {
	boost::system::error_code ec;
	boost::asio::write(clientSocket,
		boost::asio::buffer(data, size),
		boost::asio::transfer_all(), ec);
	if (ec)
		throw PartyCommunicationException("Error while writing. " + ec.message());
}

CommPartyTCPSynced::~CommPartyTCPSynced() {
	acceptor_.close();
	serverSocket.close();
	clientSocket.close();
}

/*****************************************/
/* CommPartyTcpSslSynced                 */
/*****************************************/
CommPartyTcpSslSynced::CommPartyTcpSslSynced(boost::asio::io_service& ioService, SocketPartyData me, 
	SocketPartyData other, string certificateChainFile, string password, string privateKeyFile, 
	string tmpDHFile, string clientVerifyFile) : ioServiceServer(ioService), ioServiceClient(ioService),
	acceptor_(ioService, tcp::endpoint(tcp::v4(), me.getPort()))
{
	this->me = me;
	this->other = other;
	
	// create server SSL context and socket
	boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
	//ctx.set_verify_mode(boost::asio::ssl::verify_none);
	ctx.set_options(
		boost::asio::ssl::context::default_workarounds
		| boost::asio::ssl::context::no_sslv2
		| boost::asio::ssl::context::single_dh_use);

	ctx.set_password_callback([password](std::size_t max_length, 
		boost::asio::ssl::context::password_purpose purpose) {return password; });
	ctx.use_certificate_chain_file(certificateChainFile);
	ctx.use_private_key_file(privateKeyFile, boost::asio::ssl::context::pem);
	ctx.use_tmp_dh_file(tmpDHFile);
	serverSocket = new ssl_socket(ioService, ctx);
	
	// create client SSL context and socket
	boost::asio::ssl::context clientCtx(boost::asio::ssl::context::sslv23);
	clientCtx.load_verify_file(clientVerifyFile);
	clientSocket = new ssl_socket(ioService, clientCtx);

};

void CommPartyTcpSslSynced::join(int sleepBetweenAttempts, int timeout) {
	int     totalSleep = 0;
	bool    isAccepted = false;
	bool    isConnected = false;
	// establish connections
	while (!isConnected || !isAccepted) {
		try {
			if (!isConnected) {
				tcp::resolver resolver(ioServiceClient);
				tcp::resolver::query query(other.getIpAddress().to_string(), to_string(other.getPort()));
				tcp::resolver::iterator endpointIterator = resolver.resolve(query);
				boost::asio::connect(clientSocket->lowest_layer(), endpointIterator);
				clientSocket->handshake(boost::asio::ssl::stream_base::client);
				isConnected = true;
			}
		}
		catch (const boost::system::system_error& ex)
		{
			if (totalSleep > timeout)
			{
				cerr << "Failed to connect after timeout, aboting!";
				throw ex;
			}
			cout << "Failed to connect. sleeping for " << sleepBetweenAttempts << 
				" milliseconds, " << ex.what() << endl;
			this_thread::sleep_for(chrono::milliseconds(sleepBetweenAttempts));
			totalSleep += sleepBetweenAttempts;
		}
		if (!isAccepted) {
			boost::system::error_code ec;
			tcp::endpoint peer_endpoint;
			acceptor_.accept(serverSocket->lowest_layer(), peer_endpoint);
			serverSocket->handshake(boost::asio::ssl::stream_base::server, ec);
			if(ec)
				throw PartyCommunicationException("Handshake failed. " + ec.message());
			isAccepted = true;
		}
	}
}


void CommPartyTcpSslSynced::write(const byte* data, int size) {
	boost::system::error_code ec;
	boost::asio::write(*clientSocket,
		boost::asio::buffer(data, size),
		boost::asio::transfer_all(), ec);
	if (ec)
		throw PartyCommunicationException("Error while writing. " + ec.message());
}

CommPartyTcpSslSynced::~CommPartyTcpSslSynced() {
	acceptor_.close();
	serverSocket->lowest_layer().close();
	clientSocket->lowest_layer().close();
}


