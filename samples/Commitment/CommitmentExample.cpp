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

shared_ptr<CmtCommitter> getCommitter(shared_ptr<CommParty> channel, CommitmentParams sdp) {
	shared_ptr<CmtCommitter> sds;
	if (sdp.protocolName == "Pedersen") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenCommitter>(channel, dlog);
	} if (sdp.protocolName == "PedersenWithProofs") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenWithProofsCommitter>(channel, dlog, 80);
	} else if (sdp.protocolName == "PedersenTrapdoor") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenTrapdoorCommitter>(channel, dlog);
	} else if (sdp.protocolName == "PedersenHash") {
		auto dlog = make_shared<OpenSSLDlogECF2m>("K-283");
		auto hash = make_shared<OpenSSLSHA256>();
		sds = make_shared<CmtPedersenHashCommitter>(channel, dlog, hash);
	} else if (sdp.protocolName == "SimpleHash") {
		sds = make_shared<CmtSimpleHashCommitter>(channel);
	} else if (sdp.protocolName == "ElGamalOnGroupElement") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtElGamalOnGroupElementCommitter>(channel, dlog);
	} else if (sdp.protocolName == "ElGamalOnByteArray") {
		sds = make_shared<CmtElGamalOnByteArrayCommitter>(channel);
	} else if (sdp.protocolName == "ElGamalHash") {
		sds = make_shared<CmtElGamalHashCommitter>(channel);
	}

	return sds;
}

shared_ptr<CmtReceiver> getReceiver(shared_ptr<CommParty> channel, CommitmentParams sdp) {
	shared_ptr<CmtReceiver> sds;
	if (sdp.protocolName == "Pedersen") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenReceiver>(channel, dlog);
	} if (sdp.protocolName == "PedersenWithProofs") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenWithProofsReceiver>(channel, dlog, 80);
	} else if (sdp.protocolName == "PedersenTrapdoor") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtPedersenTrapdoorReceiver>(channel, dlog);
	} else if (sdp.protocolName == "PedersenHash") {
		auto dlog = make_shared<OpenSSLDlogECF2m>("K-283");
		auto hash = make_shared<OpenSSLSHA256>();
		sds = make_shared<CmtPedersenHashReceiver>(channel, dlog, hash);
	} else if (sdp.protocolName == "SimpleHash") {
		sds = make_shared<CmtSimpleHashReceiver>(channel);
	} else if (sdp.protocolName == "ElGamalOnGroupElement") {
		auto dlog = make_shared<OpenSSLDlogECF2m>();
		sds = make_shared<CmtElGamalOnGroupElementReceiver>(channel, dlog);
	} else if (sdp.protocolName == "ElGamalOnByteArray") {
		sds = make_shared<CmtElGamalOnByteArrayReceiver>(channel);
	} else if (sdp.protocolName == "ElGamalHash") {
		sds = make_shared<CmtElGamalHashReceiver>(channel);
	}


	return sds;
}

int mainCommitment(string side, string configPath) {
	auto sdp = readCommitmentConfig(configPath);
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
			auto committer = getCommitter(server, sdp);
			auto val = committer->sampleRandomCommitValue();
			cout << "the committed value is:" << val->toString() << endl;
			committer->commit(val, 0);
			committer->decommit(0);

			if (sdp.protocolName.find("WithProofs") != string::npos) {
				auto prover = dynamic_pointer_cast<CmtWithProofsCommitter>(committer);
				prover->proveKnowledge(0);
				prover->proveCommittedValue(0);
			}
		}
		else if (side == "2") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto receiver = getReceiver(server, sdp);
			auto commitment = receiver->receiveCommitment();
			auto result = receiver->receiveDecommitment(0);
			if (result == NULL) {
				cout << "commitment failed" << endl;
			} else
				cout << "the committed value is:" << result->toString() << endl;;


			if (sdp.protocolName.find("WithProofs") != string::npos) {
				auto verifier = dynamic_pointer_cast<CmtWithProofsReceiver>(receiver);
				bool verified = verifier->verifyKnowledge(0);
				cout << "knowledge verifer output: " << (verified ? "Success" : "Failure") << endl;
				cout << "verified committed value: " << verifier->verifyCommittedValue(0)->toString() << endl;
			}
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

