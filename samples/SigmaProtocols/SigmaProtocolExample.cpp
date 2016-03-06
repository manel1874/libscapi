#include "SigmaProtocolExample.hpp"

void run_prover(std::shared_ptr<ChannelServer> server, SigmaDlogParams sdp, ProverVerifierExample& pe) {
	auto zp_params = make_shared<ZpGroupParams>(sdp.q, sdp.g, sdp.p);
	auto dg = make_shared<OpenSSLDlogZpSafePrime>(zp_params);
	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	auto g = dg->getGenerator();
	auto h = dg->exponentiate(g, sdp.w);
	auto proverComputation = make_shared<SigmaDlogProverComputation>(dg, sdp.t,
		get_seeded_random());
	auto proverInput = make_shared<SigmaDlogProverInput>(h, sdp.w);
	pe.prove(server, proverComputation, dg, proverInput);
}

void run_verifier(shared_ptr<ChannelServer> server, SigmaDlogParams sdp, ProverVerifierExample& pe) {
	auto zp_params = make_shared<ZpGroupParams>(sdp.q, sdp.g, sdp.p);
	auto openSSLdg = make_shared<OpenSSLDlogZpSafePrime>(zp_params, get_seeded_random());
	auto dg = std::static_pointer_cast<DlogGroup>(openSSLdg);
	server->try_connecting(500, 5000); // sleep time=500, timeout = 5000 (ms);
	auto g = dg->getGenerator();
	auto h = dg->exponentiate(g, sdp.w);
	auto commonInput = make_shared<SigmaDlogCommonInput>(h);
	auto verifierComputation = make_shared<SigmaDlogVerifierComputation>(
		dg, sdp.t, get_seeded_random());
	auto msg1 = make_shared<SigmaGroupElementMsg>(h->generateSendableData());
	auto msg2 = make_shared<SigmaBIMsg>();
	bool verificationPassed = pe.verify(server, verifierComputation, msg1, msg2, commonInput, openSSLdg);
	cout << "Verifer output: " << (verificationPassed ? "Success" : "Failure") << endl;

}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		SigmaUsage(argv[0]);
		return 1;
	}
	auto sdp = readSigmaConfig(argv[2]);
	string side(argv[1]);

	boost::asio::io_service io_service;
	SocketPartyData proverParty(sdp.proverIp, sdp.proverPort);
	SocketPartyData verifierParty(sdp.verifierIp, sdp.verifierPort);
	shared_ptr<ChannelServer> server = (side == "1")?
		make_shared<ChannelServer>(io_service, proverParty, verifierParty) : 
		make_shared<ChannelServer>(io_service, verifierParty, proverParty);
	boost::thread t(boost::bind(&boost::asio::io_service::run, &io_service));
	auto pve = getProverVerifier(sdp);
	try {
		if (side == "1") {
			run_prover(server, sdp, *pve);
		}
		else if (side == "2") {
			run_verifier(server, sdp, *pve);
		}
		else {
			SigmaUsage(argv[0]);
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