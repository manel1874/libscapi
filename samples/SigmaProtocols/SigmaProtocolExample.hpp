#pragma once

#include <boost/thread/thread.hpp>
#include "../../include/comm/TwoPartyComm.hpp"
#include "../../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"
#include "../../include/interactive_mid_protocols/ZeroKnowledge.hpp"
#include "../../include/primitives/DlogOpenSSL.hpp"
#include "../../include/infra/Scanner.hpp"
#include "../../include/infra/ConfigFile.hpp"

struct SigmaDlogParams {
	biginteger w;
	biginteger p;
	biginteger q;
	biginteger g;
	int t;
	IpAdress proverIp;
	IpAdress verifierIp;
	int proverPort;
	int verifierPort;
	string protocolName;

	SigmaDlogParams(biginteger w, biginteger p, biginteger q, biginteger g, int t, 
		IpAdress proverIp, IpAdress verifierIp, int proverPort, int verifierPort, 
		string protocolName) {
		this->w = w; // witness
		this->p = p; // group order - must be prime
		this->q = q; // sub group order - prime such that p=2q+1
		this->g = g; // generator of Zq
		this->t = t; // soundness param must be: 2^t<q
		this->proverIp = proverIp;
		this->verifierIp = verifierIp;
		this->proverPort = proverPort;
		this->verifierPort = verifierPort;
		this->protocolName = protocolName;
	};
};

SigmaDlogParams readSigmaConfig(string config_file) {
	ConfigFile cf(config_file);
	string input_section = cf.Value("", "input_section");
	biginteger p = biginteger(cf.Value(input_section, "p"));
	biginteger q = biginteger(cf.Value(input_section, "q"));
	biginteger g = biginteger(cf.Value(input_section, "g"));
	biginteger w = biginteger(cf.Value(input_section, "w"));
	int t = stoi(cf.Value(input_section, "t"));
	string proverIpStr = cf.Value("", "proverIp");
	string verifierIpStr = cf.Value("", "verifierIp");
	int proverPort = stoi(cf.Value("", "proverPort"));
	int verifierPort = stoi(cf.Value("", "verifierPort"));
	auto proverIp = IpAdress::from_string(proverIpStr);
	auto verifierIp = IpAdress::from_string(verifierIpStr);
	string protocolName = cf.Value("", "protocolName");
	return SigmaDlogParams(w, p, q, g, t, proverIp, verifierIp, proverPort, verifierPort, protocolName);
};

void SigmaUsage(char * argv0) {
	std::cerr << "Usage: " << argv0 << " <1(=prover)|2(=verifier)> config_file_path" << std::endl;
}

class ProverVerifierExample {
public:
	virtual void prove(shared_ptr<ChannelServer> server, 
		shared_ptr<SigmaDlogProverComputation> proverComputation, 
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) = 0;
	virtual bool verify(shared_ptr<ChannelServer> server, 
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) = 0;
};

class SimpleDlogSigma : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<ChannelServer> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) override {
		auto sp = new SigmaProtocolProver(server, proverComputation);
		cout << "--> running simple sigma dlog prover" << endl;
		sp->prove(proverinput);
	}
	virtual bool verify(shared_ptr<ChannelServer> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override{
		auto v = new SigmaProtocolVerifier(server, verifierComputation, msgA, msgZ);
		cout << "--> running simple sigma dlog verify" << endl;
		bool verificationPassed = v->verify(commonInput.get());
		delete v;
		return verificationPassed;
	}
};

class PedersenZKSigma : public ProverVerifierExample {
public:
	virtual void prove(shared_ptr<ChannelServer> server,
		shared_ptr<SigmaDlogProverComputation> proverComputation,
		shared_ptr<DlogGroup> dg,
		shared_ptr<SigmaDlogProverInput> proverinput) {
		auto sp = new ZKPOKFromSigmaCmtPedersenProver(server, proverComputation, dg);
		cout << "--> running pedersen prover" << endl;
		sp->prove(proverinput);
	}
	virtual bool verify(shared_ptr<ChannelServer> server,
		shared_ptr<SigmaDlogVerifierComputation> verifierComputation,
		shared_ptr<SigmaGroupElementMsg> msgA,
		shared_ptr<SigmaBIMsg> msgZ,
		shared_ptr<SigmaDlogCommonInput> commonInput,
		shared_ptr<DlogGroup> dg) override {
		auto emptyTrap = make_shared<CmtRTrapdoorCommitPhaseOutput>();
		auto v = new ZKPOKFromSigmaCmtPedersenVerifier(server, verifierComputation,
			get_seeded_random64(), emptyTrap, dg);
		cout << "--> running pedersen verify" << endl;
		bool verificationPassed = v->verify(commonInput, msgA, msgZ);
		delete v;
		return verificationPassed;
	}
};


shared_ptr<ProverVerifierExample> getProverVerifier(SigmaDlogParams sdp)
{
	shared_ptr<ProverVerifierExample> sds;
	if(sdp.protocolName=="Simple")
		sds = make_shared<SimpleDlogSigma>();
	else if(sdp.protocolName=="ZKPedersen")
		sds = make_shared<PedersenZKSigma>();

	return sds;
}
