#include "CommitmentExample.hpp"

CommitmentParams readCommitmentConfig(string config_file) {
	ConfigFile cf(config_file);
	string proverIpStr = cf.Value("", "proverIp");
	string verifierIpStr = cf.Value("", "verifierIp");
	int proverPort = stoi(cf.Value("", "proverPort"));
	int verifierPort = stoi(cf.Value("", "verifierPort"));
	auto proverIp = IpAdress::from_string(proverIpStr);
	auto verifierIp = IpAdress::from_string(verifierIpStr);
	string protocolName = cf.Value("", "protocolName");
	return CommitmentParams(proverIp, verifierIp, proverPort, verifierPort, protocolName);
};

void CommitmentUsage() {
	std::cerr << "Usage: ./libscapi_examples <1(=committer)|2(=receiver)> config_file_path" << std::endl;
}

shared_ptr<CmtCommitter> getCommitter(shared_ptr<CommParty> channel, shared_ptr<DlogGroup> dlog, CommitmentParams sdp) {
	shared_ptr<CmtCommitter> sds;
	if (sdp.protocolName == "Pedersen") {
		sds = make_shared<CmtPedersenCommitter>(channel, dlog);
	} else if (sdp.protocolName == "PedersenTrapdoor") {
		sds = make_shared<CmtPedersenTrapdoorCommitter>(channel, dlog);
	}

	return sds;
}

shared_ptr<CmtReceiver> getReceiver(shared_ptr<CommParty> channel, shared_ptr<DlogGroup> dlog, CommitmentParams sdp) {
	shared_ptr<CmtReceiver> sds;
	if (sdp.protocolName == "Pedersen") {
		sds = make_shared<CmtPedersenReceiver>(channel, dlog);
	}
	else if (sdp.protocolName == "PedersenTrapdoor") {
		sds = make_shared<CmtPedersenTrapdoorReceiver>(channel, dlog);
	}

	return sds;
}

int mainCommitment(string side, string configPath) {
	auto sdp = readCommitmentConfig(configPath);
	auto dlog = make_shared<OpenSSLDlogECF2m>();
	boost::asio::io_service io_service;
	SocketPartyData committerParty(sdp.committerIp, sdp.committerPort);
	SocketPartyData receiverParty(sdp.receiverIp, sdp.receiverPort);
	shared_ptr<CommParty> server = (side == "1") ?
		make_shared<CommPartyTCPSynced>(io_service, committerParty, receiverParty) :
		make_shared<CommPartyTCPSynced>(io_service, receiverParty, committerParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	
	try {
		if (side == "1") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto committer = getCommitter(server, dlog, sdp);
			auto val = committer->sampleRandomCommitValue();
			cout << "the committed value is:" << val->toString();
			committer->commit(val.get(), 0);
			committer->decommit(0);
		}
		else if (side == "2") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto receiver = getReceiver(server, dlog, sdp);
			auto commitment = receiver->receiveCommitment();
			auto result = receiver->receiveDecommitment(0);
			cout << "the committed value is:" << result->toString();
		}
		else {
			CommitmentUsage();
			return 1;
		}
	}
	catch (const logic_error& e) {
		// Log error message in the exception object
		cerr << e.what();
	}
	io_service.stop();
	t.join();
	return 0;
}

