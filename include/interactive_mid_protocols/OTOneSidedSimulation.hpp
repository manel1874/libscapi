#pragma once
#include "OT.hpp"
#include "ZeroKnowledge.hpp"
#include "SigmaProtocolDlog.hpp"
#include "../primitives/Kdf.hpp"
#include "../primitives/PrfOpenSSL.hpp"

/**
* Abstract class for OT with one sided simulation sender.
* This class is an implementation of Oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.
*
* OT with one sided simulation have two modes: one is on ByteArray and the second is on GroupElement.
* The different is in the input and output types and the way to process them.
* In spite that, there is a common behavior for both modes which this class is implementing.<p>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHSenderAbs : public OTSender {
	/*
	This class runs the following protocol:
	IF NOT VALID_PARAMS(G,q,g)
	REPORT ERROR and HALT
	WAIT for message a from R
	DENOTE the tuple a received by (x, y, z0, z1)
	Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.
	If output is REJ, REPORT ERROR (cheat attempt) and HALT
	IF NOT
	*	z0 = z1
	*	x, y, z0, z1 in G
	REPORT ERROR (cheat attempt)
	SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1}
	COMPUTE:
	*	w0 = x^u0 * g^v0
	*	k0 = (z0)^u0 * y^v0
	*	w1 = x^u1 * g^v1
	*	k1 = (z1)^u1 * y^v1
	*	c0 = x0 XOR KDF(|x0|,k0)
	*	c1 = x1 XOR KDF(|x1|,k1)
	SEND (w0, c0) and (w1, c1) to R
	OUTPUT nothing

	*/

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	*/
	OTOneSidedSimDDHSenderAbs(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE: in byteArray scenario:
	*	*	c0 = x0 XOR KDF(|x0|,k0)
	*	*	c1 = x1 XOR KDF(|x1|,k1)
	*	OR in GroupElement scenario:
	*	*	c0 = x0 * k0
	*	*	c1 = x1 * k1"
	* @param k1
	* @param k0
	* @param w1
	* @param w0
	* @param input
	* @return tuple contains (w0, c0, w1, c1) to send to the receiver.
	*/
	virtual shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) = 0;

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	ZKPOKFromSigmaCmtPedersenVerifier zkVerifier;
	biginteger qMinusOne;

	/**
	* Runs the following line from the protocol:
	* "WAIT for message (h0,h1) from R"
	* @param channel
	* @return the received message.
	* @throws IOException if failed to receive a message.
	* @throws ClassNotFoundException
	*/
	OTRGroupElementQuadMsg waitForMessageFromReceiver(CommParty* channel);

	/**
	* Runs the following line from the protocol:
	* "Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG.
	*  Use common input x.
	*	If output is REJ, REPORT ERROR (cheat attempt) and HALT".
	* @param channel
	* @param h common input (x)
	* @return the received message.
	* @throws CheatAttemptException
	* @throws IOException if failed to receive a message.
	* @throws ClassNotFoundException
	* @throws InvalidDlogGroupException
	*/
	void runZKPOK(const shared_ptr<GroupElement> & h);

	/**
	* Runs the following lines from the protocol:
	* "IF NOT
	*	*	z0 != z1
	*	*	x, y, z0, z1 in the DlogGroup
	*	REPORT ERROR (cheat attempt)"
	* @param z1
	* @param z0
	* @param y
	* @param x
	* @return the received message.
	* @throws CheatAttemptException
	*/
	void checkReceivedTuple(GroupElement* x, GroupElement* y, GroupElement* z0, GroupElement* z1);

	/**
	* Runs the following lines from the protocol:
	* "SEND (w0, c0) and (w1, c1) to R"
	* @param channel
	* @param message to send to the receiver
	* @throws IOException if failed to send the message.
	*/
	void sendTupleToReceiver(CommParty* channel, OTSMsg* message);

public:

	/**
	* Runs the transfer phase of the protocol. <p>
	* This is the part of the protocol where the sender input is necessary.<p>
	* "WAIT for message a from R<p>
	*	DENOTE the tuple a received by (x, y, z0, z1)<p>
	*	Run the verifier in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x.<p>
	*	If output is REJ, REPORT ERROR (cheat attempt) and HALT<p>
	*	IF NOT<p>
	*	*	z0 = z1<p>
	*	*	x, y, z0, z1 in G<p>
	*	REPORT ERROR (cheat attempt)<p>
	*	SAMPLE random values u0,u1,v0,v1 <-  {0, . . . , q-1} <p>
	*	COMPUTE:<p>
	*	*	w0 = x^u0 * g^v0<p>
	*	*	k0 = (z0)^u0 * y^v0<p>
	*	*	w1 = x^u1 * g^v1<p>
	*	*	k1 = (z1)^u1 * y^v1 <p>
	*	*	c0 = x0 XOR KDF(|x0|,k0)<p>
	*	*	c1 = x1 XOR KDF(|x1|,k1) <p>
	*	SEND (w0, c0) and (w1, c1) to R<p>
	*	OUTPUT nothing"
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.<p>
*
* This class derived from OTOneSidedSimDDHSenderAbs and implements the functionality
* related to the GroupElement inputs.<p>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHOnGroupElementSender : public OTOneSidedSimDDHSenderAbs, OneSidedSimulation {
	
protected:

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			c0 = x0 * k0
	*			c1 = x1 * k1"
	* @param input MUST be OTSOnGroupElementInput.
	* @param w0
	* @param w1
	* @param k0
	* @param k1
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) override;

public:

	/**
	* Constructor that sets the given channel, dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws CheatAttemptException
	*/
	OTOneSidedSimDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(), 
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) : OTOneSidedSimDDHSenderAbs(channel, random, dlog) {}
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.<p>
*
* This class derived from OTOneSidedSimDDHSenderAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<P>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHOnByteArraySender : public OTOneSidedSimDDHSenderAbs, OneSidedSimulation {

private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.

protected:
	/**
	* Runs the following lines from the protocol:
	* "COMPUTE:
	*			c0 = x0 XOR KDF(|x0|,k0)
	*			c1 = x1 XOR KDF(|x1|,k1)"
	* @param  iput NUST be an instance of OTSOnByteArrayInput.
	* @param w0
	* @param w1
	* @param k0
	* @param k1
	* @return tuple contains (u, v0, v1) to send to the receiver.
	*/
	shared_ptr<OTSMsg> computeTuple(OTSInput* input, GroupElement* w0, GroupElement* w1, GroupElement* k0, GroupElement* k1) override; 

public:
	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws CheatAttemptException
	* @throws ClassNotFoundException
	* @throws IOException if failed to receive a message during pre process.
	*/
	OTOneSidedSimDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(new OpenSSLHMAC("SHA-256"))) 
		: OTOneSidedSimDDHSenderAbs(channel, random, dlog), kdf(kdf) {}
};

/**
* Abstract class for OT with one sided simulation receiver.
* This class is an implementation of Oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.
*
* OT with one sided simulation have two modes: one is on ByteArray and the second is on GroupElement.
* The different is in the input and output types and the way to process them.
* In spite that, there is a common behavior for both modes which this class is implementing.<P>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHReceiverAbs : public OTReceiver {

	/*
	This class runs the following protocol:
	IF NOT VALID_PARAMS(G,q,g)
	REPORT ERROR and HALT
	SAMPLE random values alpha, beta, gamma in {0, . . . , q-1}
	COMPUTE a as follows:
	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))
	SEND a to S
	Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x and private input alpha.
	WAIT for message pairs (w0, c0) and (w1, c1)  from S
	In ByteArray scenario:
	IF  NOT
	1. w0, w1 in the DlogGroup, AND
	2. c0, c1 are binary strings of the same length
	REPORT ERROR
	COMPUTE kSigma = (wSigma)^beta
	OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	In GroupElement scenario:
	IF  NOT
	1. w0, w1, c0, c1 in the DlogGroup
	REPORT ERROR
	COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	OUTPUT  xSigma = cSigma * (kSigma)^(-1)

	*/

protected:
	shared_ptr<DlogGroup> dlog;

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given DlogGroup is not valid.
	*/
	OTOneSidedSimDDHReceiverAbs(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random, const shared_ptr<DlogGroup> & dlog);

	/**
	* Runs the following lines from the protocol:
	* "In ByteArray scenario:
	*		IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	*	In GroupElement scenario:
	*		IF  NOT
	*			1. w0, w1, c0, c1 in the DlogGroup
	*		   REPORT ERROR
	* In ByteArray scenario:
	*		COMPUTE kSigma = (wSigma)^beta
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)
	*	In GroupElement scenario:
	*		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	virtual shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) = 0;

private:
	shared_ptr<PrgFromOpenSSLAES> random;
	ZKPOKFromSigmaCmtPedersenProver zkProver;
	biginteger qMinusOne;

	/**
	* Runs the following lines from the protocol:
	* "COMPUTE a as follows:
	*			1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)
	*			2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))"
	* @param sigma input for the protocol
	* @param alpha random value sampled in the protocol
	* @param beta random value sampled in the protocol
	* @param gAlpha g^alpha
	* @return OTRPrivacyOnlyMessage contains the tuple (x, y, z0, z1).
	*/
	OTRGroupElementQuadMsg computeTuple(byte sigma, biginteger & alpha, biginteger & beta, GroupElement* gAlpha);

	/**
	* Runs the following line from the protocol:
	* "SEND a to S"
	* @param channel
	* @param a the tuple to send to the sender.
	* @throws IOException
	*/
	void sendTupleToSender(CommParty* channel, OTRGroupElementQuadMsg a);

public:
	
	/**
	* Runs the transfer phase of the OT protocol.<p>
	* This is the part of the protocol where the receiver input is necessary.<p>
	* "SAMPLE random values alpha, beta, gamma in {0, . . . , q-1} <p>
	*	COMPUTE a as follows:<p>
	*	1.	If sigma = 0 then a = (g^alpha, g^beta, g^(alpha*beta), g^gamma)<p>
	*	2.	If sigma = 1 then a = (g^alpha, g^beta, g^gamma, g^(alpha*beta))<p>
	*	SEND a to S<p>
	*	Run the prover in ZKPOK_FROM_SIGMA with Sigma protocol SIGMA_DLOG. Use common input x and private input alpha.<p>
	*	WAIT for message pairs (w0, c0) and (w1, c1)  from S<p>
	*	In ByteArray scenario:<p>
	*		IF  NOT <p>
	*			1. w0, w1 in the DlogGroup, AND<p>
	*			2. c0, c1 are binary strings of the same length<p>
	*			  REPORT ERROR<p>
	*		COMPUTE kSigma = (wSigma)^beta<p>
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)<p>
	*	In GroupElement scenario:<p>
	*		IF  NOT <p>
	*			1. w0, w1, c0, c1 in the DlogGroup<p>
	*			  REPORT ERROR<p>
	*		COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)<p>
	*		OUTPUT  xSigma = cSigma * (kSigma)^(-1)"<p>
	* @return OTROutput, the output of the protocol.
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.<p>
*
* This class derived from OTOneSidedSimDDHReceiverAbs and implements the functionality
* related to the GroupElement inputs.<p>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell. <P>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHOnGroupElementReceiver : public OTOneSidedSimDDHReceiverAbs, OneSidedSimulation {

private:

	/**
	* Run the following line from the protocol:
	* "IF  NOT
	*		1. w0, w1, c0, c1 in the DlogGroup
	*	REPORT ERROR"
	* @param c1
	* @param c0
	* @param w1
	* @param w0
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* w0, GroupElement* w1, GroupElement* c0, GroupElement* c1);

protected:
	/**
	* Run the following lines from the protocol:
	* "IF  NOT
	*		1. w0, w1, c0, c1 in the DlogGroup
	*	REPORT ERROR
	*  COMPUTE (kSigma)^(-1) = (wSigma)^(-beta)
	*	OUTPUT  xSigma = cSigma * (kSigma)^(-1)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) override;

public:

	/**
	* Constructor that sets the given dlogGroup and random.
	* @param dlog must be DDH secure.
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTOneSidedSimDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233")) : OTOneSidedSimDDHReceiverAbs(channel, random, dlog) {}

};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption that achieves
* privacy for the case that the sender is corrupted and simulation in the case that the receiver
* is corrupted.<p>
*
* This class derived from OTOneSidedSimDDHReceiverAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.3 page 185 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 4.3 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTOneSidedSimDDHOnByteArrayReceiver : public OTOneSidedSimDDHReceiverAbs, OneSidedSimulation {

private:
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.

	/**
	* Run the following line from the protocol:
	* "IF NOT
	*		1. w0, w1 in the DlogGroup, AND
	*		2. c0, c1 are binary strings of the same length
	*	   REPORT ERROR"
	* @param w0
	* @param w1
	* @param c0
	* @param c1
	* @throws CheatAttemptException if there was a cheat attempt during the execution of the protocol.
	*/
	void checkReceivedTuple(GroupElement* w0, GroupElement* w1, vector<byte> & c0, vector<byte> & c1);

protected:

	/**
	* Run the following lines from the protocol:
	* "IF  NOT
	*			1. w0, w1 in the DlogGroup, AND
	*			2. c0, c1 are binary strings of the same length
	*		   REPORT ERROR
	* COMPUTE kSigma = (wSigma)^beta
	* OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,kSigma)"
	* @param sigma input of the protocol
	* @param beta random value sampled in the protocol
	* @param message received from the sender
	* @return OTROutput contains xSigma
	* @throws CheatAttemptException
	*/
	shared_ptr<OTROutput> getMsgAndComputeXSigma(CommParty* channel, byte sigma, biginteger & beta) override;

public:

	/**
	* Constructor that sets the given dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	OTOneSidedSimDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"),
		const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(new OpenSSLHMAC("SHA-256")))
		: OTOneSidedSimDDHReceiverAbs(channel, random, dlog), kdf(kdf) {}

};



