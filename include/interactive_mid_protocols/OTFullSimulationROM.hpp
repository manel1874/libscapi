#pragma once
#include "OTFullSimulation.hpp"
#include "../primitives/RandomOracle.hpp"

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption
* that achieves full simulation in the random oracle model.<p>
*
* This class derived from OTFullSimROMDDHSenderAbs and implements the functionality
* related to the group elements inputs.
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. <P>
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimROMDDHOnGroupElementSender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given , dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param ro random oracle
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimROMDDHOnGroupElementSender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());


	/**
	* Runs the transfer phase of the protocol.<p>
	*	Transfer Phase (with inputs x0,x1)<p>
	*		WAIT for message from R<p>
	*		DENOTE the values received by (g,h) <p>
	*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	*		COMPUTE c0 = x0 * v0<p>
	*		COMPUTE c1 = x1 * v1<p>
	*		SEND (u0,c0) and (u1,c1) to R<p>
	*		OUTPUT nothing<p>
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the sender side in oblivious transfer based on the DDH assumption that achieves
* full simulation in the random oracle model.<p>
*
* This class derived from OTFullSimROMDDHSenderAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. <P>
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimROMDDHOnByteArraySender : public OTSender, Malicious, StandAlone {

private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.
	
public:
	

	/**
	* Constructor that sets the given , dlogGroup, kdf and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param ro random oracle
	* @param random
	* @throws SecurityLevelException if the given DlogGroup is not DDH secure.
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the sender suspects that the receiver is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*/
	OTFullSimROMDDHOnByteArraySender(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(new OpenSSLHMAC("SHA-256")),
		const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

	/**
	* Runs the transfer phase of the protocol.<p>
	*	Transfer Phase (with inputs x0,x1)<p>
	*		WAIT for message from R<p>
	*		DENOTE the values received by (g,h) <p>
	*		COMPUTE (u0,v0) = RAND(g0,g,h0,h)<p>
	*		COMPUTE (u1,v1) = RAND(g1,g,h1,h)<p>
	*		COMPUTE c0 = x0 XOR KDF(|x0|,v0)<p>
	*		COMPUTE c1 = x1 XOR KDF(|x1|,v1)<p>
	*		SEND (u0,c0) and (u1,c1) to R<p>
	*		OUTPUT nothing<p>
	*/
	void transfer(CommParty* channel, OTSInput* input) override;
};

/**
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption
* that achieves full simulation in the random oracle model.<p>
*
* This class derived from OTFullSimROMDDHReceiverAbs and implements the functionality
* related to the GroupElement inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. <P>
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimROMDDHOnGroupElementReceiver : public OTReceiver, Malicious, StandAlone {

private:
private:
	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	
	/**
	* Constructor that sets the given dlogGroup, random oracle and random.
	* @param dlog must be DDH secure.
	* @param ro random oracle
	* @param random
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*
	*/
	OTFullSimROMDDHOnGroupElementReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

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
* Concrete implementation of the receiver side in oblivious transfer based on the DDH assumption
*  that achieves full simulation in the random oracle model.<p>
*
* This class derived from OTFullSimROMDDHReceiverAbs and implements the functionality
* related to the byte array inputs.<p>
*
* For more information see Protocol 7.5.1 page 201 of <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell;
* this is the protocol of [PVW] adapted to the stand-alone setting and using a Fiat-Shamir proof instead of interactive zero-knowledge. <P>
*
* The pseudo code of this protocol can be found in Protocol 4.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class OTFullSimROMDDHOnByteArrayReceiver : public OTReceiver, Malicious, StandAlone {

private:

	shared_ptr<DlogGroup> dlog;
	shared_ptr<PrgFromOpenSSLAES> random;
	shared_ptr<RandomOracle> ro;
	shared_ptr<KeyDerivationFunction> kdf; //Used in the calculation.
	shared_ptr<OTFullSimPreprocessPhaseValues> preprocessOutput; //Values calculated by the preprocess phase.

public:
	/**
	* Constructor that sets the given dlogGroup, kdf, random oracle and random.
	* @param dlog must be DDH secure.
	* @param kdf
	* @param ro random oracle
	* @param random
	* @throws ClassNotFoundException if there was a problem during the serialization mechanism in the preprocess phase.
	* @throws CheatAttemptException if the receiver suspects that the sender is trying to cheat in the preprocess phase.
	* @throws IOException if there was a problem during the communication in the preprocess phase.
	* @throws CommitValueException can occur in case of ElGamal commitment scheme.
	*
	*/
	OTFullSimROMDDHOnByteArrayReceiver(const shared_ptr<CommParty> & channel, const shared_ptr<PrgFromOpenSSLAES> & random = make_shared<PrgFromOpenSSLAES>(),
		const shared_ptr<DlogGroup> & dlog = make_shared<OpenSSLDlogECF2m>("K-233"), const shared_ptr<KeyDerivationFunction> & kdf = make_shared<HKDF>(new OpenSSLHMAC("SHA-256")),
		const shared_ptr<RandomOracle> & oracle = make_shared<HKDFBasedRO>());

	/**
	*
	* Run the following part of the protocol:
	* Transfer Phase (with input sigma) <p>
	*		SAMPLE a random value r <- {0, . . . , q-1} <p>
	*		COMPUTE<p>
	*		4.	g = (gSigma)^r<p>
	*		5.	h = (hSigma)^r<p>
	*		SEND (g,h) to S<p>
	*		WAIT for messages (u0,c0) and (u1,c1) from S<p>
	*		IF  NOT<p>
	*			u0, u1 in G, AND<p>
	*			c0, c1 are binary strings of the same length<p>
	*		      REPORT ERROR<p>
	*		OUTPUT  xSigma = cSigma XOR KDF(|cSigma|,(uSigma)^r)<p>
	*/
	shared_ptr<OTROutput> transfer(CommParty* channel, OTRInput* input) override;
};
