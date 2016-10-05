#pragma once

#include "OT.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "ZeroKnowledge.hpp"
#include "SigmaProtocolDH.hpp"

/**
* This class holds the Group Elements calculated in the preprocess phase.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimPreprocessPhaseValues {

private:
	shared_ptr<GroupElement> g0, g1, h0, h1; //Values calculated by the preprocess phase.

public:
	OTFullSimPreprocessPhaseValues(const shared_ptr<GroupElement> & g0, const shared_ptr<GroupElement> & g1, const shared_ptr<GroupElement> & h0, 
		const shared_ptr<GroupElement> & h1) : g0(g0), g1(g1), h0(h0), h1(h1){}

	shared_ptr<GroupElement> getG0() {	return g0;	}

	shared_ptr<GroupElement> getG1() {	return g1;	}

	shared_ptr<GroupElement> getH0() {	return h0;	}

	shared_ptr<GroupElement> getH1() {	return h1;	}
};

/**
* Concrete implementation of OT with full simulation receiver message. This implementation is common for OT on byteArray and on GroupElement.
* The message contains tuple of three GroupElements - (h0, h1, g1).
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHReceiverMsg : public NetworkSerialized {

private:
	shared_ptr<GroupElementSendableData> h0;
	shared_ptr<GroupElementSendableData> h1;
	shared_ptr<GroupElementSendableData> g1;

public:
	OTFullSimDDHReceiverMsg(const shared_ptr<GroupElementSendableData> & g1, const shared_ptr<GroupElementSendableData> & h0,
		const shared_ptr<GroupElementSendableData> & h1) : h0(h0), h1(h1), g1(g1){}

	shared_ptr<GroupElementSendableData> getH0() { return h0; }

	shared_ptr<GroupElementSendableData> getH1() { return h1;}

	shared_ptr<GroupElementSendableData> getG1() { return g1;}
};

/**
* This class execute  the preprocess phase of OT's that achieve full simulation.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*
class OTFullSimSenderPreprocessUtil {
private:
	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	* @throws ClassNotFoundException
	* @throws IOException if failed to receive a message.
	*
	static OTFullSimDDHReceiverMsg waitForFullSimMessageFromReceiver(CommParty* channel) {
		vector<byte> raw_msg;
		channel->readWithSizeIntoVector(raw_msg);

		// create an empty OTRGroupElementPairMsg and initialize it with the received data. 
		OTFullSimDDHReceiverMsg msg;
		msg.initFromByteVector(raw_msg);

		return msg; 
	}

public:

	/**
	* Runs the preprocess phase of the OT protocol, where the sender input is not yet necessary.<p>
	* "WAIT for message from R<p>
	* DENOTE the values received by (g1,h0,h1) <p>
	* Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1).<p>
	* If output is REJ, REPORT ERROR (cheat attempt) and HALT."<p>
	* @param channel used to communicate between the parties.
	* @param dlog
	* @param zkVerifier used to verify the ZKPOK_FROM_SIGMA
	* @return the values calculated in the preprocess
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*
	static OTFullSimPreprocessPhaseValues preProcess(CommParty* channel, DlogGroup* dlog, ZKPOKVerifier* zkVerifier) {

		//Wait for message from R
		OTFullSimDDHReceiverMsg message = waitForFullSimMessageFromReceiver(channel);

		auto g1 = dlog->reconstructElement(true, message.getG1().get());
		auto h0 = dlog->reconstructElement(true, message.getH0().get());
		auto h1 = dlog->reconstructElement(true, message.getH1().get());

		//Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH.
		auto g1Inv = dlog->getInverse(g1.get());
		auto h1DivG1 = dlog->multiplyGroupElements(h1.get(), g1Inv.get());

		//If the output of the Zero Knowledge Proof Of Knowledge is REJ, throw CheatAttempException.
		SigmaDHCommonInput input(g1, h0, h1DivG1);
		if (!zkVerifier->verify(&input, , )) {
			throw CheatAttemptException("ZKPOK verifier outputed REJECT");
		}

		return OTFullSimPreprocessPhaseValues(dlog->getGenerator(), g1, h0, h1);
	}
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves full simulation.<p>
* This implementation can also be used as batch OT that achieves full simulation. <p>
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. <p>
*
* This class derived from OTFullSimDDHSenderAbs and implements the functionality
* related to the GroupElement inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*
class OTFullSimDDHOnGroupElementSender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;

	OTFullSimPreprocessPhaseValues preprocessOutput; //Values calculated by the preprocess phase.

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	*
	OTFullSimDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) {

		//The underlying dlog group must be DDH secure.
		auto ddh = dynamic_pointer_cast<DDH>(dlog);
		if (ddh == NULL) {
			throw SecurityLevelException("DlogGroup should have DDH security level");
		}

		// Runs the following part of the protocol:
		//	IF NOT VALID_PARAMS(G,q,g0)
		//   REPORT ERROR and HALT.
		if (!dlog->validateGroup())
			throw InvalidDlogGroupException("The given DlogGRoup is not valid");

		this->dlog = dlog;
		this->random = random;

		//Create the underlying ZKPOK
		ZKPOKFromSigmaCmtPedersenVerifier zkVerifier(channel, make_shared<SigmaDHVerifierComputation>(dlog, 80), , dlog);

		// Some OT protocols have a pre-process stage before the transfer. 
		// Usually, pre process is done once at the beginning of the protocol and will not be executed later, 
		// and then the transfer function could be called multiple times.
		// We implement the preprocess stage at construction time. 
		// A protocol that needs to call preprocess after the construction time, should create a new instance.
		//Call the utility function that executes the preprocess phase.
		preprocessOutput = OTFullSimSenderPreprocessUtil::preProcess(channel, dlog, zkVerifier);
	}

	/**
	* Runs the transfer phase of the OT protocol.<p>
	*	Transfer Phase (with inputs x0,x1)<p>
	*	WAIT for message from R<p>
	*	DENOTE the values received by (g,h) <p>
	*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	*	COMPUTE c0 = x0 * v0<p>
	*	COMPUTE c1 = x1 * v1<p>
	*	SEND (u0,c0) and (u1,c1) to R<p>
	*	OUTPUT nothing<p>
	*
	void transfer(CommParty* channel, OTSInput* input) override {
		//Creates the utility class that executes the transfer phase.
		OTFullSimOnGroupElementSenderTransferUtil transferUtil(dlog, random);
		transferUtil.transfer(channel, input, preprocessOutput);

	}
};

*/