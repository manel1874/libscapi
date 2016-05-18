#pragma once
#include "SigmaProtocol.hpp"
#include "../mid_layer/ElGamalEnc.hpp"
#include "SigmaProtocolDlog.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalPrivateKey verifier and simulator.<P>
* In SigmaElGamalPrivateKey protocol, the common input contains an ElGamal public key.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalPrivateKeyCommonInput : public SigmaCommonInput {

private:
	ElGamalPublicKey publicKey;

public:
	/**
	* Sets the publlic key.
	* @param publicKey
	*/
	SigmaElGamalPrivateKeyCommonInput(ElGamalPublicKey publicKey) : publicKey(publicKey) {}

	/**
	* Returns the public key.
	*/
	ElGamalPublicKey getPublicKey() { return publicKey; }

};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaElGamalPrivateKeyProver.<P>
* In SigmaElGamalPrivateKey protocol, the prover gets an ElGamal public and private keys.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalPrivateKeyProverInput : public SigmaProverInput {

private:
	shared_ptr<SigmaElGamalPrivateKeyCommonInput> input;
	ElGamalPrivateKey privateKey;

public:
	/**
	* Sets the keys.
	* @param pubKey
	* @param privKey
	*/
	SigmaElGamalPrivateKeyProverInput(ElGamalPublicKey pubKey, ElGamalPrivateKey privKey) : privateKey(privKey) {
		input = make_shared<SigmaElGamalPrivateKeyCommonInput>(pubKey);
	}

	/**
	* Returns the private key.
	*/
	ElGamalPrivateKey getPrivateKey() {	return privateKey; }

	shared_ptr<SigmaCommonInput> getCommonInput() override { return input; }
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that it knows the private key to an ElGamal public key.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.8 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalPrivateKeySimulator : public SigmaSimulator {

	/*
	This class uses an instance of SigmaDlogSimulator with:
	Common DlogGroup
	input: h (the public key).
	*/

private:
	SigmaDlogSimulator dlogSim; //underlying SigmaDlogSimulator to use.

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalPrivateKeySimulator(shared_ptr<DlogGroup> dlog, int t) : dlogSim(dlog, t) {}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return dlogSim.getSoundnessParam(); }

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input, vector<byte> challenge) override; 

	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
	* @return the output of the computation - (a, e, z).
	* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(SigmaCommonInput* input) override; 
};

/**
* Concrete implementation of Sigma Protocol prover computation. <p>
*
* This protocol is used for a party to prove that it knows the private key to an ElGamal public key.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.8 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalPrivateKeyProverComputation : public SigmaProverComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDlogProver with:
	Common DlogGroup
	input: h (the public key) and a value w<- Zq such that h=g^w (the private key).

	*/

private:
	SigmaDlogProverComputation sigmaDlog;	//underlying SigmaDlogProver to use.
	shared_ptr<DlogGroup> dlog;				//We need the DlogGroup instance in order to calculate the input for the underlying SigmaDlogProver
	int t;
	mt19937 random;

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaElGamalPrivateKeyProverComputation(shared_ptr<DlogGroup> dlog, int t);

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDlog.getSoundnessParam(); }

	/**
	* Computes the first message of the protocol.
	* @param input MUST be an instance of SigmaElGamalPrivateKeyProverInput.
	* @return the computed message
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyProverInput.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(shared_ptr<SigmaProverInput> input) override; 

	/**
	* Computes the second message of the protocol.
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(vector<byte> challenge) override; 

	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDlogSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaElGamalPrivateKeySimulator>(dlog, t);
	}

};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
*
* This protocol is used for a party to verify that the prover knows the private key to an ElGamal public key.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.8 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class SigmaElGamalPrivateKeyVerifierComputation :public SigmaVerifierComputation, DlogBasedSigma {

	/*
	This class uses an instance of SigmaDlogVerifier with:
	Common DlogGroup
	Common input: h (the public key).

	*/

private:
	SigmaDlogVerifierComputation sigmaDlog;		//underlying SigmaDlogVerifier to use.

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	* @throws InvalidDlogGroupException if the given dlog is invalid.
	*/
	SigmaElGamalPrivateKeyVerifierComputation(shared_ptr<DlogGroup> dlog, int t) : sigmaDlog(dlog, t) {}

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return sigmaDlog.getSoundnessParam();	}

	/**
	* Samples the challenge e <- {0,1}^t.
	*/
	void sampleChallenge() override { sigmaDlog.sampleChallenge(); }

	/**
	* Sets the given challenge.
	* @param challenge
	*/
	void setChallenge(vector<byte> challenge) override { sigmaDlog.setChallenge(challenge); }

	/**
	* Returns the sampled challenge.
	* @return the challenge.
	*/
	vector<byte> getChallenge() override { return sigmaDlog.getChallenge(); }

	/**
	* Verifies the proof.
	* @param z second message from prover
	* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyCommonInput.
	* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
	* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
	*/
	bool verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) override; 
};




