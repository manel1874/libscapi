#pragma once
#include "SigmaProtocol.hpp"
#include <map>

/**
* Concrete implementation of SigmaProtocol message.
* This message contains an array the interpolated polynomial, array of SigmaProtocolMsg and challenges.
* The prover used this message to send the first message to the verifier.
*/
class SigmaORMultipleSecondMsg : public SigmaProtocolMsg {

private:
	byte** polynomial;
	vector<SigmaProtocolMsg *> z;
	byte** challenges;

	SigmaORMultipleSecondMsg(byte** polynomBytes, vector<SigmaProtocolMsg*> z, byte** challenges) {
		this->polynomial = polynomBytes;
		this->z = z;
		this->challenges = challenges;
	};

	byte** getPolynomial() { return polynomial; };

	vector<SigmaProtocolMsg*> getMessages() { return z; };

	byte** getChallenges() { return challenges; };
};


/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolORMultiple verifier and simulator.<p>
* In SigmaProtocolORMultiple, the common input contains an array of inputs to all of
* its underlying objects and k - number of true statements.
*/
class SigmaORMultipleCommonInput : public SigmaCommonInput {
public:

	/**
	* Sets the input array and the number of statements that have a witness.
	* @param input contains inputs for all the underlying sigma protocol.
	* @param k number of statements that have a witness.
	*/
	SigmaORMultipleCommonInput(vector<SigmaCommonInput *> & input, int k) {
		sigmaInputs = input;
		this->k = k;
	};

	/**
	* Returns the input array contains inputs for all the underlying sigma protocol.
	*/
	vector<SigmaCommonInput *> getInputs() { return sigmaInputs; };

	/**
	* Returns the number of statements that have a witness.
	*/
	int getK() { return k; };

private:
	vector<SigmaCommonInput *> sigmaInputs;
	int k; //number of statements that have a witness.
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaProtocolORMultipleProver.<p>
* This input contains inputs for the true statements(including witnesses) and input for the false atatements(without witnesses).
*/
class SigmaORMultipleProverInput  : public SigmaProverInput {
private:
	//hold the prover private input.
	map<int, SigmaProverInput*> proverInputs;

	//Hold the common parameters of the statement where the prover does not know the witness.
	map<int, SigmaCommonInput*> simulatorInputs;

public:
	/**
	* Sets the inputs for the underlying provers and simulators.
	* @param proverInputs
	* @param simulatorInputs
	*/
	SigmaORMultipleProverInput(map<int, SigmaProverInput*> proverInputs, map<int, SigmaCommonInput*> simulatorInputs) {
		this->proverInputs = proverInputs;
		this->simulatorInputs = simulatorInputs;
	}

	/**
	* Returns an array holds the inputs for the underlying provers.
	* @return an array holds the inputs for the underlying provers.
	*/
	map<int, SigmaProverInput*> getProversInput() { return proverInputs; };

	/**
	* Returns an array holds the inputs for the underlying simulators.
	* @return an array holds the inputs for the underlying simulators.
	*/
	map<int, SigmaCommonInput*> getSimulatorsInput() { return simulatorInputs; };

	shared_ptr<SigmaCommonInput> getCommonParams() override;
};


/**
* Concrete implementation of Sigma Protocol prover computation.<p>
* This protocol is used for a prover to convince a verifier that at least k out of n statements are true,
* where each statement can be proven by an associated Sigma protocol.<p>
* The pseudo code of this protocol can be found in Protocol 1.16 of pseudo codes document at 
* {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaORMultipleProverComputation : public SigmaProverComputation {

	/*
	* Let (ai,ei,zi) denote the steps of a Sigma protocol SigmaI for proving that xi is in LRi
	* Let I denote the set of indices for which P has witnesses
	This class computes the following calculations:
	For every j not in I, SAMPLE a random element ej <- GF[2^t]
	For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)
	For every i in I, RUN the prover P on statement xi to get first message ai
	SET a=(a1,...,an)

	INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)
	For every i in I, SET ei = Q(i)
	For every i in I, COMPUTE the response zi to (ai, ei) in SigmaI using input (xi,wi)
	The message is Q,e1,z1,...,en,zn (where by Q we mean its coefficients)
	*/
private:
	map<int, SigmaProverComputation *> provers;	// Underlying Sigma protocol's provers to the OR calculation.
	map<int, SigmaSimulator* > simulators;		// Underlying Sigma protocol's simulators to the OR calculation.
	int len;											// Number of underlying provers.
	int t;												// Soundness parameter.
	int k;												//number of witnesses.
	std::mt19937 random;								// The indexes of the statements which the prover knows the witnesses.
	
	SigmaORMultipleProverInput * input;					// Used in computeFirstMsg function.

	vector<vector<byte>> hallenges;								// Will hold the challenges to the underlying provers/simulators.
																// Some will be calculate in sampleRandomValues function and some in compueSecondMsg. 

	map<int, SigmaSimulatorOutput*> simulatorsOutput;	// We save this because we calculate it in computeFirstMsg and using 
																		// it after that, in computeSecondMsg

	vector<long> fieldElements;								//Will hold pointers to the sampled field elements, 
															//we save the pointers to save the creation of the elements again in computeSecondMsg function.

	//Initializes the field GF2E with a random irreducible polynomial with degree t.
	//private native void initField(int t, int seed);

	////Creates random field elements to be the challenges.
	//private native byte[][] createRandomFieldElements(int numElements, long[] fieldElements);

	////Interpolates the points to get a polynomial.
	//private native long interpolate(byte[] e, long[] fieldElements, int[] indexes);

	////Calculates the challenges for the statements with the witnesses.
	//private native byte[][] getRestChallenges(long polynomial, int[] indexesInI);

	////Returns the byteArray of the polynomial coefficients.
	//private native byte[][] getPolynomialBytes(long polynomial);

	////Deletes the allocated memory of the polynomial and the field elements.
	//private native void deletePointers(long polynomial, long[] fieldElements);

	/**
	* Align the given array to t length. Adds zeros in the beginning.
	* @param array to align
	* @return the aligned array.
	*/
	byte* alignToT(byte* array);

	/**
	* Sets the inputs for each one of the underlying prover.
	* @param input MUST be an instance of SigmaORMultipleProverInput.
	*/
	void checkInput(SigmaProverInput * in);

public:

	/**
	* Constructor that gets the underlying provers.
	* @param provers array of SigmaProverComputation, where each object represent a statement
	* 		  and the prover wants to prove to the verify that the OR of all statements are true.
	* @param t soundness parameter. t MUST be equal to all t values of the underlying provers object.
	*/
	SigmaORMultipleProverComputation(map<int, SigmaProverComputation *> provers,
		map<int, SigmaSimulator *> simulators, int t, mt19937 random);
	
	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() { return t; };

	/**
	* Computes the first message of the protocol.<p>
	* "For every j not in I, SAMPLE a random element ej <- GF[2^t]<p>
	*  For every j not in I, RUN the simulator on statement xj and challenge ej to get transcript (aj,ej,zj)<p>
	For every i in I, RUN the prover P on statement xi to get first message ai<p>
	SET a=(a1,...,an)".
	* @param input MUST be an instance of SigmaORMultipleInput.
	* @return SigmaMultipleMsg contains a1, ..., am.
	*/
	SigmaProtocolMsg* computeFirstMsg(SigmaProverInput * in);

	/**
	* Computes the second message of the protocol.<p>
	* "INTERPOLATE the points (0,e) and {(j,ej)} for every j not in I to obtain a degree n-k polynomial Q (s.t. Q(0)=e and Q(j)=ej for every j not in I)<p>
	For every i in I, SET ei = Q(i)<p>
	For every i in I, COMPUTE the response zi to (ai, ei) in Sigmai using input (xi,wi)<p>
	The message is Q,e1,z1,...,en,zn (where by Q we mean its coefficients)".<p>
	* @param challenge
	* @return SigmaMultipleMsg contains z1, ..., zm.
	*/
	SigmaProtocolMsg* computeSecondMsg(byte* challenge);
	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaORMultipleSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override;

};


