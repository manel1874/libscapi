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
/* NativeChannel						 */
/*****************************************/

void NativeChannel::start_listening()
{
	boost::asio::async_read(serverSocket,
		boost::asio::buffer(read_msg_.data(), Message::header_length),
		boost::bind(&NativeChannel::handle_read_header, this,
			boost::asio::placeholders::error));
	boost::asio::ip::tcp::no_delay option(true);
	serverSocket.set_option(option);
}

void NativeChannel::connect(bool bSynced) {
	tcp::resolver resolver(io_service_client_);
	tcp::resolver::query query(other.getIpAddress().to_string(), to_string(other.getPort()));
	tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
	if (bSynced)
	{// blocking!
		boost::asio::connect(clientSocket, endpoint_iterator);
		m_IsConnected = true;
		boost::asio::ip::tcp::no_delay option(true);
		clientSocket.set_option(option);
	}
	else
		boost::asio::async_connect(clientSocket, endpoint_iterator,
			boost::bind(&NativeChannel::handle_connect, this,
				boost::asio::placeholders::error));
	
}

void NativeChannel::handle_connect(const boost::system::error_code& error)
{
	if (!error)
	{
		Logger::log("Channel (" + me.to_log_string() + ") - succesfully connected to peer ("
			+ other.to_log_string() + ")");
		m_IsConnected = true;
		boost::asio::ip::tcp::no_delay option(true);
		clientSocket.set_option(option);
	}
	else
		Logger::log("Channel (" + me.to_log_string() + ") - failed to connect to peer ("
			+ other.to_log_string() + ")!!");
}

void NativeChannel::write(const Message& msg)
{
	io_service_client_.post(boost::bind(&NativeChannel::do_write, this, msg));
}

void NativeChannel::write_fast(const Message& msg)
{
	boost::system::error_code ignored_error;
	boost::asio::write(clientSocket,
		boost::asio::buffer(msg.data(), msg.length()),
		boost::asio::transfer_all(), ignored_error);
}

void NativeChannel::close()
{
	Logger::log("Channel (" + me.to_log_string() + ") - closing");
	io_service_client_.post(boost::bind(&NativeChannel::do_close, this));
}

void NativeChannel::do_write(const Message& msg)
{
	bool write_in_progress = !write_msgs_.empty();
	write_msgs_.push_back(msg);
	if (!write_in_progress)
	{
		boost::asio::async_write(clientSocket,
			boost::asio::buffer(write_msgs_.front().data(),
				write_msgs_.front().length()),
			boost::bind(&NativeChannel::handle_write, this,
				boost::asio::placeholders::error));
	}
}

void NativeChannel::do_write_fast(byte* data, int len)
{
	boost::system::error_code ignored_error;
	boost::asio::write(clientSocket,
		boost::asio::buffer(data, len),
		boost::asio::transfer_all(), ignored_error);
}

void NativeChannel::handle_write(const boost::system::error_code& error)
{
	if (!error)
	{
		write_msgs_.pop_front();
		if (!write_msgs_.empty())
		{
			boost::asio::async_write(clientSocket,
				boost::asio::buffer(write_msgs_.front().data(),
					write_msgs_.front().length()),
				boost::bind(&NativeChannel::handle_write, this,
					boost::asio::placeholders::error));
		}
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when writing message: "
			+ error.message());
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_read_header(const boost::system::error_code& error)
{
	if (!error && read_msg_.decode_header())
	{
		boost::asio::async_read(serverSocket,
			boost::asio::buffer(read_msg_.body(), read_msg_.body_length()),
			boost::bind(&NativeChannel::handle_read_body, this,
				boost::asio::placeholders::error));
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when reading message header: "
			+ error.message());
		cout << "Channel( " + me.to_log_string() + 
			"error when reading message header: " + error.message() << endl;
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_read_body(const boost::system::error_code& error)
{
	if (!error)
	{
		handle_msg(read_msg_);
		boost::asio::async_read(serverSocket,
			boost::asio::buffer(read_msg_.data(), Message::header_length),
			boost::bind(&NativeChannel::handle_read_header, this,
				boost::asio::placeholders::error));
	}
	else
	{
		Logger::log("Channel( " + me.to_log_string() + "error when reading message body: "
			+ error.message());
		m_IsConnected = false;
		do_close();
	}
}

void NativeChannel::handle_msg(const Message& msg) {
	int m_len = read_msg_.body_length();
	auto v = new vector<byte>(m_len);
	if (m_len>0)
		memcpy(&(v->at(0)), read_msg_.body(), m_len);
	std::unique_lock<std::mutex> lk(m);
	read_msgs_.push_back(v);
	lk.unlock();
	cv.notify_one();
}

vector<byte> * NativeChannel::read_one() {
	// Wait until main() sends data
	std::unique_lock<std::mutex> lk(m);
	while (read_msgs_.empty())
		cv.wait(lk);

	auto item = read_msgs_.front();
	read_msgs_.pop_front();
	return item;
}

/*****************************************/
/* ChannelServer						 */
/*****************************************/

void ChannelServer::write(shared_ptr<byte> data, int size) {
	msg.body_length(size);
	memcpy(msg.body(), &(data.get()[0]), msg.body_length());
	msg.encode_header();
	channel->write(msg);
}

void ChannelServer::write_fast(byte* data, int size) {
	msg.body_length(size);
	memcpy(msg.body(), data, msg.body_length());
	msg.encode_header();
	channel->write_fast(msg);
}

void ChannelServer::write_fast(const string & data) {
	msg.body_length(data.size());
	memcpy(msg.body(), data.c_str(), msg.body_length());
	msg.encode_header();
	channel->write_fast(msg);
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


