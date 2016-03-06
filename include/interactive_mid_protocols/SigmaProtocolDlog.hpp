#pragma once
#include "SigmaProtocol.hpp"
#include "../primitives/Dlog.hpp"

/**
* Concrete implementation of SigmaProtocol message. <p>
* This message contains one GroupElement sendable data and used when the prover sends a message to the verifier.
*/
class SigmaGroupElementMsg : public SigmaProtocolMsg {
public:
	SigmaGroupElementMsg(shared_ptr<GroupElementSendableData> el) {  this->element = el;  };
	shared_ptr<GroupElementSendableData> getElement() { return element; };
	// SerializedNetwork implementation:
	void initFromByteArray(byte* arr, int size) override { element->initFromByteArray(arr, size); };
	shared_ptr<byte> toByteArray() override{ return element->toByteArray();  };
	int getSerializedSize() override { return element->getSerializedSize(); };

private:
	shared_ptr<GroupElementSendableData> element=NULL;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDlog verifier and simulator.<p>
* In SigmaProtocolDlog, the common input contains a GroupElement h.
*/
class SigmaDlogCommonInput : public SigmaCommonInput {
public:
	SigmaDlogCommonInput(shared_ptr<GroupElement> h) { this->h = h; };
	shared_ptr<GroupElement> getH() { return h; };
private:
	shared_ptr<GroupElement> h;
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that it knows the discrete log of the value h in G.<P>
*
* For more information see protocol 6.1.1, page 148 of Hazay - Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at{ @link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE a random z <- Zq
	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)
	OUTPUT (a,e,z).
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	*/
	SigmaDlogSimulator(shared_ptr<DlogGroup> dlog, int t, std::mt19937 random);
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; };
	/**
	* Computes the simulator computation, using the given challenge.<p>
	* "SAMPLE a random z <- Zq <p>
	*	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)<p>
	*	OUTPUT (a,e,z)".	<p>
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, eSize, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input, 
		shared_ptr<byte> challenge, int challenge_size) override;
	/**
	* Computes the simulator computation, using random challenge.<p>
	* "SAMPLE a random z <- Zq<p>
	*	COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)<p>
	*	OUTPUT (a,e,z)".	<p>
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input) override;

private:
	shared_ptr<DlogGroup> dlog; 		//Underlying DlogGroup.
	int t;					//Soundness parameter.
	std::mt19937 random;
	biginteger qMinusOne;
	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	*/
	bool checkChallengeLength(shared_ptr<byte> challenge, int challenge_size) {
		// if the challenge's length is equal to t, return true. else, return false.
		biginteger e = decodeBigInteger(challenge.get(), challenge_size);
		return (e >= 0) && (e < mp::pow(biginteger(2), t));
	}
	/**
	* Checks the validity of the given soundness parameter.
	*/
	bool checkSoundnessParam();
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaDlogProver.<p>
* In SigmaProtocolDlog, the prover gets a GroupElement h and a BigInteger w such that g^w = h.
*/
class SigmaDlogProverInput : public SigmaProverInput {
public:
	/**
	* Sets the given h and w, such that g^w = h.
	*/
	SigmaDlogProverInput(shared_ptr<GroupElement> h, biginteger w) {
		params = make_shared<SigmaDlogCommonInput>(h);
		this->w = w;
	};
	/**
	* Returns w element, such that g^w = h.
	*/
	biginteger getW() { return w; };
	shared_ptr<SigmaCommonInput> getCommonParams() override { return params; };

private:
	shared_ptr<SigmaDlogCommonInput> params;
	biginteger w;
};


/**
* Concrete implementation of Sigma Protocol prover computation.<p>
* This protocol is used for a prover to convince a verifier that it knows the discrete log of the value h in G. <p>
* This implementation is based on Schnorr's sigma protocol for Dlog Group, see reference in Protocol 6.1.1, page 148 of Hazay-Lindell.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogProverComputation : public SigmaProverComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE a random r in Zq
	COMPUTE a = g^r
	COMPUTE z = r + ew mod q
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	*/
	SigmaDlogProverComputation(std::shared_ptr<DlogGroup> dlog, int t, std::mt19937 random);
	int getSoundnessParam() override { return t; };
	/**
	* Computes the first message from the protocol.<p>
	* "SAMPLE a random r in Zq<p>
	*  COMPUTE a = g^r". <p>
	* @param input MUST be an instance of SigmaDlogProverInput.
	* @return the computed message
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(shared_ptr<SigmaProverInput> input) override;
	/**
	* Computes the secong message from the protocol.<p>
	* "COMPUTE z = (r + ew) mod q".<p>
	* @param challenge<p>
	* @return the computed message.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(byte* challenge, int challenge_size) override;
	/**
	* Returns the simulator that matches this sigma protocol prover.
	*/
	shared_ptr<SigmaSimulator> getSimulator() override { 
		auto res = make_shared<SigmaDlogSimulator>(dlog, t, random);
		return res; };

private:
	shared_ptr<DlogGroup> dlog;				// Underlying DlogGroup.
	int t;	 						// soundness parameter in BITS.
	std::mt19937 random;
	shared_ptr<SigmaDlogProverInput> input;	// Contains h and w.
	biginteger r;				// The value chosen in the protocol.
	biginteger qMinusOne;

	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	*/
	bool checkChallengeLength(byte* challenge, int challenge_size) {
		biginteger e = decodeBigInteger(challenge, challenge_size);
		return (e >= 0) && (e < mp::pow(biginteger(2), t)); // 0 <= e < 2^t
	};
	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam();
};

/**
* Concrete implementation of SigmaSimulatorOutput, used by SigmaDlogSimulator.<p>
* It contains the a, e, z types used in the above mentioned concrete simulator.
*/
class SigmaDlogSimulatorOutput : public SigmaSimulatorOutput {
public:
	/**
	* Sets the output of the simulator.
	*/
	SigmaDlogSimulatorOutput(shared_ptr<SigmaGroupElementMsg> a, shared_ptr<byte> e, int eSize, 
		shared_ptr<SigmaBIMsg> z) {
		this->a = a;
		this->e = e;
		this->eSize = eSize;
		this->z = z;
	}
	/**
	* Returns first message.
	*/
	shared_ptr<SigmaProtocolMsg> getA() override { return a; };
	/**
	* Returns the challenge.
	*/
	shared_ptr<byte> getE() override { return e; };
	/**
	* Returns the challenge size.
	*/
	int getESize() override { return eSize; };
	/**
	* Returns second message.
	*/
	shared_ptr<SigmaProtocolMsg> getZ() override { return z; };


private:
	shared_ptr<SigmaGroupElementMsg> a;
	shared_ptr<byte> e;
	int eSize;
	shared_ptr<SigmaBIMsg> z;
};

/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
* This protocol is used for a prover to convince a verifier that it knows the discrete log of the value h in G. <P>
* This implementation is based on Schnorr's sigma protocol for Dlog Group, see reference in Protocol 6.1.1, page 148 of Hazay-Lindell..<p>
* The pseudo code of this protocol can be found in Protocol 1.1 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.
*/
class SigmaDlogVerifierComputation : public SigmaVerifierComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = ah^e
	*/
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaDlogVerifierComputation(std::shared_ptr<DlogGroup> dlog, int t, std::mt19937 random);
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; }
	/**
	* Samples the challenge to use in the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;
	/**
	* Sets the given challenge and its size.
	*/
	void setChallenge(shared_ptr<byte> challenge, int challenge_size) override {
		e = challenge;
		eSize = challenge_size;
	};
	/**
	* Returns the sampled challenge.
	*/
	pair<shared_ptr<byte>, int> getChallenge() override { return make_pair(e, eSize); };
	/**
	* Verifies the proof.<p>
	* Computes the following line from the protocol:<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g) = TRUE AND h in G AND g^z = ah^e".<p>
	* @param a first message from prover
	* @param z second message from prover
	* @param input MUST be an instance of SigmaDlogCommonInput.
	* @return true if the proof has been verified; false, otherwise.
	*/
	bool verify(shared_ptr<SigmaCommonInput> input, shared_ptr<SigmaProtocolMsg> a,
		shared_ptr<SigmaProtocolMsg> z) override;

private:
	shared_ptr<DlogGroup> dlog;		// Underlying DlogGroup.
	int t; 					// Soundness parameter in BITS.
	shared_ptr<byte> e;				// The challenge.
	int eSize;				// The challenge size.
	std::mt19937 random;

	/**
	* Checks the validity of the given soundness parameter.
	*/
	bool checkSoundnessParam();
};
