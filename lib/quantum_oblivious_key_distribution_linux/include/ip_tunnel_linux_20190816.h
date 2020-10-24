/* ###################################################################

This module was succefully compilled with:

Visual Studio						Windows SDK				Languague
2017 (v141)							10.0.17763.0			ISO C++17
2019 (v142)							10.0.18362.0			ISO C++17

###################################################################### */

# ifndef IP_TUNNEL_LINUX_H_
# define IP_TUNNEL_LINUX_H_

# include "netxpto_linux_20190816.h"

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

enum class transport_protocol { UDP, TCP };

class IPTunnel : public Block {

public:

	// ##########################################################################

	IPTunnel(std::initializer_list<Signal*> InputSig, std::initializer_list<Signal*> OutputSig) : Block(InputSig, OutputSig) {};

	void initialize(void);
	bool runBlock(void);
	void terminate(void);

	// ##########################################################################

	void setRemoteMachineIpAddress(std::string rMachineIpAddress) { remoteMachineIpAddress = rMachineIpAddress; };
	std::string getRemoteMachineIpAddress() const { return remoteMachineIpAddress; };

	void setLocalMachineIpAddress(std::string lMachineIpAddress) { localMachineIpAddress = lMachineIpAddress; };
	std::string getLocalMachineIpAddress() const { return localMachineIpAddress; };

	void setTransportMode(transport_protocol tMode) { transportProtocol = tMode; };
	transport_protocol getTransportMode() const { return transportProtocol; };

	void setPort(int p) { localMachinePort = p; };
	int getPort() const { return localMachinePort; };

	void setNumberOfTrials(int nOfTrials) { numberOfTrials = nOfTrials; };
	int getNumberOfTrials() const { return numberOfTrials; };

	void setTimeIntervalSeconds(int tIntervalSeconds) { timeIntervalSeconds = tIntervalSeconds; };
	int getTimeIntervalSeconds() const { return timeIntervalSeconds; };

	// ###########################################################################

private:
	
	// # Input Parameters ########################################################

	int numberOfTrials{ 10 };
	int timeIntervalSeconds{ 3 };

	transport_protocol transportProtocol{ transport_protocol::TCP };

	std::string localMachineIpAddress{ "127.0.0.1" };
	int localMachinePort{ 54000 };

	std::string remoteMachineIpAddress{ "127.0.0.1" };
	int remoteMachinePort{ 54000 };

	// # State Variables #########################################################

	std::vector<int> serverSocket;			// server socket
	std::vector<int> clientSocket;			// client socket

	std::vector<char> ip_tunnel_buffer;			// local buffer

	// # Private Functions ########################################################
	
	bool server_tcp();							// initializes the TCP server
	bool server_udp();							// initializes the UDP server

	bool client_tcp();							// initializes the TCP cliente
	bool client_udp();							// initializes the UDP cliente

	size_t ipTunnelSend_tcp(size_t process);	// sends data through TCP
	size_t ipTunnelSend_udp(size_t process);	// sends data through UDP

	size_t ipTunnelRecv_tcp(size_t space);		// receives data through TCP
	size_t ipTunnelRecv_udp(size_t space);		// receives data through UDP
	   
	// ###########################################################################

};

#endif
