#pragma once
#include "SigmaProtocol.hpp"

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolAND verifier and simulator.<p>
* In SigmaProtocolAND, the common input contains an array of inputs to all of its underlying objects.
*/
class SigmaANDCommonInput : public SigmaCommonInput {
public:
	/**
	* Sets the input array.
	* We pass input by value to avoid unlegal reference and since it is just pointer inside the vector
	* @param input contains inputs for all the underlying sigma protocol.
	*/
	SigmaANDCommonInput(vector<shared_ptr<SigmaCommonInput>> input) { sigmaInputs = input; };
	/**
	* Returns the input array contains inputs for all the underlying sigma protocol.
	*/
	vector<shared_ptr<SigmaCommonInput>> getInputs() { return sigmaInputs; };

private:
	vector<shared_ptr<SigmaCommonInput>> sigmaInputs;
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolANDProver.<p>
* In SigmaProtocolANDProver, the prover gets an array of inputs to all of its underlying objects.
*/
class SigmaANDProverInput : public SigmaProverInput {
public:
	/**
	* Sets the input array.
	* @param input contains inputs for all the underlying sigma protocol's provers.
	*/
	SigmaANDProverInput(vector<shared_ptr<SigmaProverInput>> input) { sigmaInputs = input; };
	/**
	* Returns the input array contains inputs for all the underlying sigma protocol's provers.
	*/
	vector<shared_ptr<SigmaProverInput>> getInputs() { return sigmaInputs; };
	shared_ptr<SigmaCommonInput> getCommonParams() override;
private:
	vector<shared_ptr<SigmaProverInput>> sigmaInputs;
};

/**
* Concrete implementation of Sigma Protocol prover computation.<p>
*
* This protocol is used for a prover to convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<P>
*
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDProverComputation : public SigmaProverComputation {
	/*
	This class computes the following calculations:
	COMPUTE all first prover messages a1,...,am
	COMPUTE all second prover messages z1,...,zm
	*/

public:
	/**
	* Constructor that sets the underlying provers.
	* @param provers array of SigmaProverComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	*/
	SigmaANDProverComputation(vector<shared_ptr<SigmaProverComputation>> provers, int t, std::mt19937 random);
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() { return t; };
	/**
	* Computes the first message the protocol.<p>
	* "COMPUTE all first prover messages a1,...,am".
	* @param input MUST be an instance of SigmaANDInput.
	* @return SigmaMultipleMsg contains a1, ..., am.
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(shared_ptr<SigmaProverInput> in) override;
	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE all second prover messages z1,...,zm".
	* @param challenge
	* @return SigmaMultipleMsg contains z1, ..., zm.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(byte* challenge, int challenge_size)override;
	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaANDSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override;

private:
	vector<shared_ptr<SigmaProverComputation>> provers;	// underlying Sigma protocol's provers to the AND calculation.
	int len;								// number of underlying provers.
	int t;									// soundness parameter.
	mt19937 random;
	/**
	* Sets the inputs for each one of the underlying prover.
	* @param input MUST be an instance of SigmaANDProverInput.
	*/
	shared_ptr<SigmaANDProverInput> checkInput(shared_ptr<SigmaProverInput> in);
};

/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
*
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDSimulator : public SigmaSimulator {
	/*
	This class computes the following calculations:
	SAMPLE random values z1 <- ZN, z2 <- Z*n, z3 <- Z*n
	COMPUTE a1 = (1+n)^z1*(z2^N/c1^e) mod N' AND a2 = c2^z1/(z3^N*c3^e) mod N'
	OUTPUT (a,e,z) where a = (a1,a2) AND z=(z1,z2,z3)
	*/
public:
	/**
	* Constructor that gets the underlying simulators.
	* @param simulators array of SigmaSimulator, where each object represent a statement
	* 		  where the prover wants to prove to the verify that that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying simulators object.
	* @param random source of randomness
	*/
	SigmaANDSimulator(vector<shared_ptr<SigmaSimulator>> simulators, int t, std::mt19937 random);
	int getSoundnessParam() override { return t; };
	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput>input, 
		shared_ptr<byte> challenge, int challenge_size) override;
	/**
	* Computes the simulator computation with a randomly chosen challenge.
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input) override;

private:
	vector<shared_ptr<SigmaSimulator>> simulators;	// Underlying Sigma protocol's simulators to the AND calculation.
	int len;							// Number of underlying simulators.
	int t;								// Soundness parameter.
	std::mt19937 random;
	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int challenge_size) {
		// if the challenge's length is equal to t, return true. else, return false.
		return (challenge_size == (t / 8) ? true : false);
	};
};

/**
* Concrete implementation of SigmaSimulatorOutput, used by SigmaANDSimulator.<p>
* It contains the a, e, z types used in the above mentioned concrete simulator.
*/
class SigmaANDSimulatorOutput : public SigmaSimulatorOutput {
public:
	/**
	* Sets the output of the simulator.
	* @param a first message
	* @param e challenge
	* @param z second message
	*/
	SigmaANDSimulatorOutput(shared_ptr<SigmaMultipleMsg> a, shared_ptr<byte> e,
		int eSize, shared_ptr<SigmaMultipleMsg> z) {
		this->a = a;
		this->e = e;
		this->eSize = eSize;
		this->z = z;
	};
	shared_ptr<SigmaProtocolMsg> getA() override { return a; };
	shared_ptr<byte> getE() override { return e; };
	int getESize() override { return eSize; }
	shared_ptr<SigmaProtocolMsg> getZ() override { return z; };

private:
	shared_ptr<SigmaMultipleMsg> a;
	shared_ptr<byte> e;
	int eSize;
	shared_ptr<SigmaMultipleMsg> z;
};

/**
* Concrete implementation of Sigma Protocol verifier computation.<p>
* This protocol is used for a prover to convince a verifier that the AND of any number of statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
* The pseudo code of this protocol can be found in Protocol 1.14 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaANDVerifierComputation : public SigmaVerifierComputation {
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF all verifier checks are ACC.
	*/

	/**
	* Constructor that gets the underlying verifiers.
	* @param verifiers array of SigmaVerifierComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that that the AND of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying verifiers object.
	* @param random source of randomness
	*/
	SigmaANDVerifierComputation(vector<shared_ptr<SigmaVerifierComputation>> & verifiers, int t, std::mt19937 random);
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; }
	/**
	* Samples the challenge of the protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;
	void setChallenge(shared_ptr<byte> challenge, int challenge_size) override {
		for (auto verifier : verifiers)
			verifier->setChallenge(challenge, challenge_size);
	}
	pair<shared_ptr<byte>,int> getChallenge() override { return make_pair(e, eSize); };
	/**
	* Computes the verification of the protocol.<p>
	* 	"ACC IFF all verifier checks are ACC".
	* @param input MUST be an instance of SigmaANDCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	*/
	bool verify(shared_ptr<SigmaCommonInput> input, shared_ptr<SigmaProtocolMsg> a,
		shared_ptr<SigmaProtocolMsg> z) override;

private:
	vector<shared_ptr<SigmaVerifierComputation>> verifiers;	// underlying Sigma protocol's verifier to the AND calculation
	int len;										// number of underlying verifiers
	shared_ptr<byte>  e;										// the challenge
	int eSize;										// the challenge size
	int t;											// soundness parameter
	std::mt19937 random;							// prg
	/**
	* Sets the inputs for each one of the underlying verifier.
	* @param input MUST be an instance of SigmaANDCommonInput.
	*/
	void checkInput(shared_ptr<SigmaCommonInput> in);
};



