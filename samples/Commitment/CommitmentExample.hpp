#pragma once
#include "../include/interactive_mid_protocols/CommitmentScheme.hpp"
#include "../include//interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../include//interactive_mid_protocols/CommitmentSchemePedersenHash.hpp"
#include "../include//interactive_mid_protocols/CommitmentSchemePedersenTrapdoor.hpp"
#include "../include//interactive_mid_protocols/CommitmentSchemeSimpleHash.hpp"

#include <boost/thread/thread.hpp>
#include "../../include/comm/Comm.hpp"
#include "../../include/infra/Scanner.hpp"
#include "../../include/infra/ConfigFile.hpp"

struct CommitmentParams {
	IpAdress committerIp;
	IpAdress receiverIp;
	int committerPort;
	int receiverPort;
	string protocolName;

	CommitmentParams(IpAdress committerIp, IpAdress receiverIp, int committerPort, int receiverPort, string protocolName) {
		this->committerIp = committerIp;
		this->receiverIp = receiverIp;
		this->committerPort = committerPort;
		this->receiverPort = receiverPort;
		this->protocolName = protocolName;
	};
};

