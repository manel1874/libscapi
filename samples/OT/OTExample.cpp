#include "OTExample.h"

OTParams readOTConfig(string config_file) {
	ConfigFile cf(config_file);
	string senderIpStr = cf.Value("", "senderIp");
	string receiverIpStr = cf.Value("", "receiverIp");
	int senderPort = stoi(cf.Value("", "senderPort"));
	int receiverPort = stoi(cf.Value("", "receiverPort"));
	auto senderIp = IpAdress::from_string(senderIpStr);
	auto receiverIp = IpAdress::from_string(receiverIpStr);
	string protocolName = cf.Value("", "protocolName");
	return OTParams(senderIp, receiverIp, senderPort, receiverPort, protocolName);
}

void OTUsage() {
	std::cerr << "Usage: ./libscapi_examples <1(=sender)|2(=receiver)> config_file_path" << std::endl;
}

shared_ptr<OTSender> getSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, OTParams sdp, const shared_ptr<DlogGroup> & dlog) {
	shared_ptr<OTSender> sender;

	if (sdp.protocolName == "SemiHonestOnGroupElement") {
		sender = make_shared<OTSemiHonestDDHOnGroupElementSender>(random, dlog);
	} else if (sdp.protocolName == "SemiHonestOnByteArray") {
		sender = make_shared<OTSemiHonestDDHOnByteArraySender>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnGroupElement") {
		sender = make_shared<OTPrivacyOnlyDDHOnGroupElementSender>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnByteArray") {
		sender = make_shared<OTPrivacyOnlyDDHOnByteArraySender>(random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnGroupElement") {
		sender = make_shared<OTOneSidedSimDDHOnGroupElementSender>(channel, random, dlog);
	}

	return sender;
}

shared_ptr<OTReceiver> getReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, OTParams sdp, const shared_ptr<DlogGroup> & dlog) {
	shared_ptr<OTReceiver> receiver;
	if (sdp.protocolName == "SemiHonestOnGroupElement") {
		receiver = make_shared<OTSemiHonestDDHOnGroupElementReceiver>(random, dlog);
	} else if (sdp.protocolName == "SemiHonestOnByteArray") {
		receiver = make_shared<OTSemiHonestDDHOnByteArrayReceiver>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnGroupElement") {
		receiver = make_shared<OTPrivacyOnlyDDHOnGroupElementReceiver>(random, dlog);
	} else if (sdp.protocolName == "PrivacyOnlyOnByteArray") {
		receiver = make_shared<OTPrivacyOnlyDDHOnByteArrayReceiver>(random, dlog);
	} else if (sdp.protocolName == "OneSidedSimulationOnGroupElement") {
		receiver = make_shared<OTOneSidedSimDDHOnGroupElementReceiver>(channel, random, dlog);
	}

	return receiver;
}

shared_ptr<OTSInput> getInput(DlogGroup* dlog, OTParams params) {
	
	if (params.protocolName == "SemiHonestOnGroupElement" || params.protocolName == "PrivacyOnlyOnGroupElement" || params.protocolName == "OneSidedSimulationOnGroupElement") {
		auto x0 = dlog->createRandomElement();
		cout << "X0 = " << x0->generateSendableData()->toString() << endl;
		auto x1 = dlog->createRandomElement();
		cout << "X1 = " << x1->generateSendableData()->toString() << endl;
		return make_shared<OTOnGroupElementSInput>(x0, x1);
	} else if (params.protocolName == "SemiHonestOnByteArray" || params.protocolName == "PrivacyOnlyOnByteArray" || params.protocolName == "OneSidedSimulationOnByteArray") {
		vector<byte> x0(10, '0'), x1(10, '1');
		cout << "x0 = " << endl;
		for (int i = 0; i < x0.size(); i++)
			cout << x0[i] << " ";
		cout << endl;
		cout << "x1 = " << endl;
		for (int i = 0; i < x1.size(); i++)
			cout << x1[i] << " ";
		cout << endl;
		return make_shared<OTOnByteArraySInput>(x0, x1);
	} 
}

void printOutput(OTROutput* output, OTParams params) {
	if (params.protocolName == "SemiHonestOnGroupElement" || params.protocolName == "PrivacyOnlyOnGroupElement" || params.protocolName == "OneSidedSimulationOnGroupElement") {
		auto out = (OTOnGroupElementROutput*)output;
		cout << "output = " << out->getXSigma()->generateSendableData()->toString() << endl;
	} else if (params.protocolName == "SemiHonestOnByteArray" || params.protocolName == "PrivacyOnlyOnByteArray" || params.protocolName == "OneSidedSimulationOnByteArray") {
		auto out = ((OTOnByteArrayROutput*)output)->getXSigma();
		cout << "output = " << endl;
		for (int i = 0; i < out.size(); i++)
			cout << out[i] << " ";
		cout << endl;
	}
}

int mainOT(string side, string configPath) {
	auto sdp = readOTConfig(configPath);
	boost::asio::io_service io_service;
	SocketPartyData senderParty(sdp.senderIp, sdp.senderPort);
	SocketPartyData receiverParty(sdp.receiverIp, sdp.receiverPort);
	shared_ptr<CommParty> server = (side == "1") ?
		make_shared<CommPartyTCPSynced>(io_service, senderParty, receiverParty) :
		make_shared<CommPartyTCPSynced>(io_service, receiverParty, senderParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));

	auto random = make_shared<PrgFromOpenSSLAES>();
	random->setKey(random->generateKey(128));
	auto dlog = make_shared<OpenSSLDlogECF2m>();
	try {
		if (side == "1") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto sender = getSender(server, random, sdp, dlog);
			auto input = getInput(dlog.get(), sdp);
			sender->transfer(server.get(), input.get());
			
		}
		else if (side == "2") {
			server->join(500, 5000); // sleep time=500, timeout = 5000 (ms);
			auto receiver = getReceiver(server, random, sdp, dlog);
			OTRBasicInput input(1);
			auto output = receiver->transfer(server.get(), &input);
			printOutput(output.get(), sdp);
		}
		else {
			OTUsage();
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

