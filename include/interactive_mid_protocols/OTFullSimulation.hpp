#pragma once
#include "OT.hpp"
#include "../primitives/DlogOpenSSL.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"
#include "ZeroKnowledge.hpp"
#include "SigmaProtocolDH.hpp"

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
	OTFullSimDDHReceiverMsg() {}

	OTFullSimDDHReceiverMsg(const shared_ptr<GroupElementSendableData> & g1, const shared_ptr<GroupElementSendableData> & h0,
		const shared_ptr<GroupElementSendableData> & h1) : h0(h0), h1(h1), g1(g1) {}

	shared_ptr<GroupElementSendableData> getH0() { return h0; }

	shared_ptr<GroupElementSendableData> getH1() { return h1; }

	shared_ptr<GroupElementSendableData> getG1() { return g1; }

	string toString();
	void initFromString(const string & row);

};

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
* This class execute  the preprocess phase of OT's that achieve full simulation.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimSenderPreprocessUtil {
private:
	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	* @throws ClassNotFoundException
	* @throws IOException if failed to receive a message.
	*/
	static OTFullSimDDHReceiverMsg waitForFullSimMessageFromReceiver(CommParty* channel);

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
	*/
	static shared_ptr<OTFullSimPreprocessPhaseValues> preProcess(CommParty* channel, DlogGroup* dlog, ZKPOKVerifier* zkVerifier);
};

/**
* This class execute  the preprocess phase of OT's that achieve full simulation.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimReceiverPreprocessUtil {
public:

	/**
	* Runs the preprocess phase of the protocol, where the receiver input is not yet necessary.<p>
	* 	"SAMPLE random values y, alpha0 <- {0, . . . , q-1} <p>
	*	SET alpha1 = alpha0 + 1 <p>
	*	COMPUTE <p>
	*    1. g1 = (g0)^y<p>
	*	  2. h0 = (g0)^(alpha0)<p>
	*	  3. h1 = (g1)^(alpha1)<p>
	*	SEND (g1,h0,h1) to S<p>
	*  Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DH. Use common input (g0,g1,h0,h1/g1) and private input alpha0."
	* @param channel
	* @param dlog
	* @param zkProver used to prove the ZKPOK_FROM_SIGMA
	* @param random
	* @return the values calculated in the preprocess
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	static shared_ptr<OTFullSimPreprocessPhaseValues> preProcess(DlogGroup* dlog, ZKPOKProver* zkProver, CommParty* channel, PrgFromOpenSSLAES* random);

};

/**
* This class execute the common functionality of the transfer function of all OT's that achieve full simulation.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimSenderTransferUtilAbs {

private:
	shared_ptr<PrgFromOpenSSLAES> random;

	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	* @throws ClassNotFoundException
	* @throws IOException if failed to receive a message.
	*/
	OTRGroupElementPairMsg waitForMessageFromReceiver(CommParty* channel);

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	* 		in the byte array scenario:
	*			COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*			COMPUTE c1 = x1 XOR KDF(|x1|,v1)
	*		in the GroupElement scenario:
	*			COMPUTE c0 = x0 * v0
	*			COMPUTE c1 = x1 * v1
	*		SEND (u0,c0) and (u1,c1) to R
	*		OUTPUT nothing
	* @param input
	* @param v1
	* @param v0
	* @param u1
	* @param u0
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	virtual shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) = 0;
	
public:
	/**
	* Sets the given dlog and random.
	* @param dlog
	* @param random
	*/
	OTFullSimSenderTransferUtilAbs(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random): dlog(dlog), random(random) {}

	/**
	* Runs the transfer phase of the OT protocol.<p>
	* Transfer Phase (with inputs x0,x1)<p>
	*	WAIT for message from R<p>
	*	DENOTE the values received by (g,h) <p>
	*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	*	in the byte array scenario:<p>
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
	*	in the GroupElement scenario:<p>
	*		COMPUTE c0 = x0 * v0<p>
	*		COMPUTE c1 = x1 * v1<p>
	*	SEND (u0,c0) and (u1,c1) to R<p>
	*	OUTPUT nothing<p>
	* This is the transfer stage of OT protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input the parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @param preprocessValues hold the values calculated in the preprocess phase.
	* @return OTROutput, the output of the protocol.
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	* @throws IOException if the send or receive functions failed
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism
	*/
	void transfer(CommParty* channel, OTSInput* input, OTFullSimPreprocessPhaseValues* preprocessValues);
};

/**
* This class executes the computations in the transfer function that related to the GroupElement inputs.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimOnGroupElementSenderTransferUtil : public OTFullSimSenderTransferUtilAbs {

protected: 
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*		c0 = x0 * v0
	*		c1 = x1 * v1"
	* @param input MUST be OTSOnGroupElementInput.
	* @param u0
	* @param u1
	* @param v0
	* @param v1
	* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) override; 

public:

	/**
	* Sets the given dlog and random.
	* @param dlog
	* @param random
	*/
	OTFullSimOnGroupElementSenderTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random)
	: OTFullSimSenderTransferUtilAbs(dlog, random) {}
};

/**
* This class executes the computations in the transfer function that related to the byte[] inputs.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimOnByteArraySenderTransferUtil : public OTFullSimSenderTransferUtilAbs {

private:
	shared_ptr<KeyDerivationFunction> kdf;

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)"
	* @param input must be a OTSOnByteArrayInput.
	* @param u0
	* @param u1
	* @param v0
	* @param v1
	* @return tuple contains (u0, c0, u1, c1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* u0, GroupElement* u1, GroupElement* v0, GroupElement* v1) override;

public:
	/**
	* Sets the given dlog, kdf and random.
	* @param dlog
	* @param kdf
	* @param random
	*/
	OTFullSimOnByteArraySenderTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random);

};

/**
* This class execute the common functionality of the transfer function of all OT's that achieve full simulation.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimReceiverTransferUtilAbs {

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	biginteger qMinusOne;

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE
	* 4.	g = (gSigma)^r
	* 5.	h = (hSigma)^r"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @return OTRFullSimMessage contains the tuple (g,h).
	*/
	OTRGroupElementPairMsg computeSecondTuple(byte sigma, biginteger & r, OTFullSimPreprocessPhaseValues* preprocessValues);

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Runs the following lines from the protocol:
	* "In ByteArray scenario:
	*		IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)
	*	In GroupElement scenario:
	*		IF  NOT
	*			1. w0, w1, c0, c1 in the DlogGroup
	*		   REPORT ERROR
	*	OUTPUT  xSigma = cSigma * (uSigma)^(-r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	virtual shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) = 0;

public:
	/**
	* Sets the given dlog and random.
	* @param dlog
	* @param random
	*/
	OTFullSimReceiverTransferUtilAbs(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random);

	/**
	*
	* Run the transfer phase of the OT protocol.<p>
	* Transfer Phase (with inputs sigma) <p>
	*		SAMPLE a random value r <- {0, . . . , q-1} <p>
	*		COMPUTE<p>
	*		4.	g = (gSigma)^r<p>
	*		5.	h = (hSigma)^r<p>
	*		SEND (g,h) to S<p>
	*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
	*		In ByteArray scenario:<p>
	*		IF  NOT<p>
	*			u0, u1 in G, AND<p>
	*			c0, c1 are binary strings of the same length<p>
	*		      REPORT ERROR<p>
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
	*		In GroupElement scenario:<p>
	*		IF  NOT<p>
	*			u0, u1, c0, c1 in G<p>
	*		      REPORT ERROR<p>
	*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)<p>
	* This is the transfer stage of OT protocol which can be called several times in parallel.<p>
	* The OT implementation support usage of many calls to transfer, with single preprocess execution. <p>
	* This way, one can execute batch OT by creating the OT receiver once and call the transfer function for each input couple.<p>
	* In order to enable the parallel calls, each transfer call should use a different channel to send and receive messages.
	* This way the parallel executions of the function will not block each other.
	* @param channel each call should get a different one.
	* @param input MUST be OTRBasicInput. The parameters given in the input must match the DlogGroup member of this class, which given in the constructor.
	* @param preprocessValues hold the values calculated in the preprocess phase.
	* @return OTROutput, the output of the protocol.
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	* @throws IOException if the send or receive functions failed
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input, OTFullSimPreprocessPhaseValues* preprocessValues);
};

/**
* This class executes the computations in the transfer function that related to the GroupElement inputs.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimOnGroupElementReceiverTransferUtil : public OTFullSimReceiverTransferUtilAbs {
private:
	
	/**
	* Run the following line from the protocol:
	* "IF  NOT
	*		1. u0, u1, c0, c1 in the DlogGroup
	*	REPORT ERROR"
	* @param c1
	* @param c0
	* @param u1
	* @param u0
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* u0, GroupElement* u1, GroupElement* c0, GroupElement* c1);

protected:
	/**
	* Run the following lines from the protocol:
	* "COMPUTE xSigma = cSigma * (uSigma)^(-r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) override;

public:
	/**
	* Sets the given dlog and random.
	* @param dlog
	* @param random
	*/
	OTFullSimOnGroupElementReceiverTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<PrgFromOpenSSLAES> & random) 
	: OTFullSimReceiverTransferUtilAbs(dlog, random) {}

};

/**
* This class executes the computations in the transfer function that related to the byte[] inputs.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimOnByteArrayReceiverTransferUtil : public OTFullSimReceiverTransferUtilAbs {

private:
	shared_ptr<KeyDerivationFunction> kdf;

	/**
	* Run the following line from the protocol:
	* "IF NOT
	*		1. u0, u1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*	   REPORT ERROR"
	* @param c1
	* @param c0
	* @param u1
	* @param u0
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* u0, GroupElement* u1, vector<byte> & c0, vector<byte> & c1);

public:
	/**
	* Sets the given dlog, kdf and random.
	* @param dlog
	* @param kdf
	* @param random
	*/
	OTFullSimOnByteArrayReceiverTransferUtil(const shared_ptr<DlogGroup> & dlog, const shared_ptr<KeyDerivationFunction> & kdf, const shared_ptr<PrgFromOpenSSLAES> & random)
		:OTFullSimReceiverTransferUtilAbs(dlog, random), kdf(kdf) {}

	/**
	* Run the following lines from the protocol:
	* "IF  NOT
	*		1. w0, w1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*		REPORT ERROR
	*	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)"
	* @param sigma input of the protocol
	* @param r random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & r) override;

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
*/
class OTFullSimDDHOnGroupElementSender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;

	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	*/
	OTFullSimDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

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
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves full simulation.<p>
* This implementation can also be used as batch OT that achieves full simulation.<p>
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. <p>
*
* This class derived from OTFullSimDDHSenderAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHOnByteArraySender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.
													
public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")));

		/**
		* Runs the transfer phase of the OT protocol.<p>
		* This is the part of the protocol where the sender's input is necessary as follows:<p>
		*	Transfer Phase (with inputs x0,x1)<p>
		*	WAIT for message from R<p>
		*	DENOTE the values received by (g,h) <p>
		*	COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
		*	COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
		*	COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
		*	COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
		*	SEND (u0,c0) and (u1,c1) to R<p>
		*	OUTPUT nothing<p>
		*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves full simulation.<p>
* This implementation can also be used as batch OT that achieves full simulation. <p>
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete OTs later
* whenever they have new inputs and wish to carry out an OT. <p>
*
* This class derived from OTFullSimDDHReceiverAbs and implements the functionality
* related to the GroupElement inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHOnGroupElementReceiver : public OTReceiver, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"));

	/**
	*
	* Run the transfer phase of the OT protocol.<p>
	* Transfer Phase (with input sigma) <p>
	*		SAMPLE a random value r <- {0, . . . , q-1} <p>
	*		COMPUTE<p>
	*		4.	g = (gSigma)^r<p>
	*		5.	h = (hSigma)^r<p>
	*		SEND (g,h) to S<p>
	*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
	*		IF  NOT<p>
	*			u0, u1, c0, c1 in G<p>
	*		      REPORT ERROR<p>
	*		OUTPUT  xSigma = cSigma * (uSigma)^(-r)<p>
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves full simulation.<p>
* This implementation can also be used as batch OT that achieves full simulation. <p>
* In batch oblivious transfer, the parties run an initialization phase and then can carry out concrete
* OTs later whenever they have new inputs and wish to carry out an OT. <p>
*
* This class derived from OTFullSimDDHReceiverAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting <P>
* The pseudo code of this protocol can be found in Protocol 4.4 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimDDHOnByteArrayReceiver : public OTReceiver, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param channel
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(make_shared<OpenSSLHMAC>("SHA-256")));

	/**
	*
	* Run the transfer phase of the protocol.<p>
	* Transfer Phase (with input sigma) <p>
	*	SAMPLE a random value r <- {0, . . . , q-1} <p>
	*	COMPUTE<p>
	*	4.	g = (gSigma)^r<p>
	*	5.	h = (hSigma)^r<p>
	*	SEND (g,h) to S<p>
	*	WAIT for messages (u0,c0) and (u1,c1) from S<p>
	*	IF  NOT<p>
	*		u0, u1 in G, AND<p>
	*		c0, c1 are binary strings of the same length<p>
	*		   REPORT ERROR<p>
	*	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;

};

