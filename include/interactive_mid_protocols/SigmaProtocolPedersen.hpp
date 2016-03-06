#pragma once

/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
* Copyright (c) 2012 - SCAPI (http://crypto.biu.ac.il/scapi)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
*
* SCAPI uses Crypto++, Miracl, NTL and Bouncy Castle. Please see these projects for any further licensing issues.
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
*
*/

#include "SigmaProtocolDlog.hpp"
#include "../primitives/Dlog.hpp"

/**
* Concrete implementation of SigmaSimulatorOutput, used by SigmaPedersenCTKnowledgeSimulator. <p>
* It contains the a, e, z types used in the above mentioned concrete simulator.
*/
class SigmaPedersenCmtKnowledgeSimulatorOutput : public SigmaSimulatorOutput {
private:
	shared_ptr<SigmaGroupElementMsg> a;
	shared_ptr<byte> e;
	int eSize;
	shared_ptr<SigmaPedersenCmtKnowledgeMsg> z;
public:
	/**
	* Sets the output of the simulator.
	* @param a first message
	* @param e challenge
	* @param z second message
	*/
	SigmaPedersenCmtKnowledgeSimulatorOutput(shared_ptr<SigmaGroupElementMsg> a, 
		shared_ptr<byte> e, shared_ptr<SigmaPedersenCmtKnowledgeMsg> z) {
		this->a = a;
		this->e = e;
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
	* Returns second message.
	*/
	shared_ptr<SigmaProtocolMsg> getZ() override { return z; };
};

/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCTKnowledge 
* verifier and simulator.<p>
* In SigmaPedersenCTKnowledge protocol, the common input contains a GroupElement h and a 
* commitment message.
*/
class SigmaPedersenCmtKnowledgeCommonInput : public SigmaCommonInput {
private:
	shared_ptr<GroupElement> h;
	shared_ptr<GroupElement> commitment;
	//void writeObject(ObjectOutputStream out) throws IOException {
	//	out.writeObject(h.generateSendableData());
	//	out.writeObject(commitment);
	//}
public:
	/**
	* Sets the given h (public key) and commitment value.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	*/
	SigmaPedersenCmtKnowledgeCommonInput(shared_ptr<GroupElement> h,
		shared_ptr<GroupElement> commitment) {
		this->h = h;
		this->commitment = commitment;
	};

	/**
	* Returns the public key used to commit.
	*/
	shared_ptr<GroupElement> getH() { return h; };

	/**
	* Returns the actual commitment value.
	*/
	shared_ptr<GroupElement> getCommitment() { return commitment; };
};

/**
* Concrete implementation of SigmaProtocol message.
* This message contains two BigIntegers and used when the SigmaPedersenCTKnowledge prover send the 
* first message to the verifier.
*/
class SigmaPedersenCmtKnowledgeMsg : public SigmaProtocolMsg {
private:
	biginteger u;
	biginteger v;
public:
	SigmaPedersenCmtKnowledgeMsg(biginteger u, biginteger v) {
		this->u = u;
		this->v = v;
	};
	biginteger getU() { return u; };
	biginteger getV() { return v; };
};


/**
* Concrete implementation of SigmaProtocol input, used by the SigmaPedersenCTKnowledgeProver.<p>
* In SigmaPedersenCTKnowledge protocol, the prover gets a GroupElement h, commitment message and
* values x,r <- Zq such that c = g^r * h^x.
*/
class SigmaPedersenCmtKnowledgeProverInput : public SigmaProverInput {
private:
	shared_ptr<SigmaPedersenCmtKnowledgeCommonInput> params;
	biginteger x;
	biginteger r;
public:
	/**
	* Sets the given h (public key), commitment value, committed value and the random value used to commit.
	* @param h public key used to commit.
	* @param commitment the actual commitment value.
	* @param x committed value
	* @param r random value used to commit
	*/
	SigmaPedersenCmtKnowledgeProverInput(shared_ptr<GroupElement> h, 
		shared_ptr<GroupElement> commitment, biginteger x, biginteger r) {
		params = make_shared<SigmaPedersenCmtKnowledgeCommonInput>(h, commitment);
		this->x = x;
		this->r = r;
	};

	/**
	* Returns the committed value.
	*/
	biginteger getX() { return x; };

	/**
	* Returns the random value used to commit.
	* @return random value used to commit.
	*/
	biginteger getR() { return r; };
	shared_ptr<SigmaCommonInput> getCommonParams() override { return params; };
};


/**
* Concrete implementation of Sigma Simulator.<p>
* This implementation simulates the case that the prover convince a verifier that that the value 
* committed to in the commitment (h, c) is x.<p>
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at 
* {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaPedersenCmtKnowledgeSimulator : public SigmaSimulator {
private:
	/*
	This class computes the following calculations:
	SAMPLE random values u, v in Zq
	COMPUTE a = h^u*g^v*c^(-e) (where -e here means -e mod q)
	OUTPUT (a,e,(u,v))
	*/
	shared_ptr<DlogGroup> dlog; 		// underlying DlogGroup.
	int t;		// soundness parameter.
	mt19937 random;

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam() {
		return (mp::pow(biginteger(2), t) > dlog->getOrder());
	};

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaPedersenCmtKnowledgeSimulator(shared_ptr<DlogGroup> dlog, int t, mt19937 random) {
		this->dlog = dlog;
		this->t = t;
		// check the soundness validity.
		if (!checkSoundnessParam()) 
			throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
		this->random = random;
	};

	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() { return t; };

	/**
	* Computes the simulator computation with the given challenge.
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeCommonInput.
	* @param challenge
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input, byte* challenge);
	/**
	* Computes the simulator computation with randomly chosen challenge.
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeInput.
	* @return the output of the computation - (a, e, z).
	*/
	shared_ptr<SigmaSimulatorOutput> simulate(shared_ptr<SigmaCommonInput> input);
	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	* @return true if the challenge length is t; false, otherwise.
	*/
	bool checkChallengeLength(int challenge_size) { return (challenge_size == (t / 8)); };
};


/**
* Concrete implementation of Sigma Protocol prover computation.<p>
* This protocol is used for a committer to prove that the value committed to in the commitment 
* (h, c) is x.<P>
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at
* {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaPedersenCmtKnowledgeProverComputation : public SigmaProverComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE random values alpha, beta <- Zq
	COMPUTE a = (h^alpha)*(g^beta)
	COMPUTE u = alpha + ex mod q and v = beta + er mod q.
	*/
private:
	shared_ptr<DlogGroup> dlog; // Underlying DlogGroup.
	int t;                 // soundness parameter in BITS.
	std::mt19937 random;
	shared_ptr<SigmaPedersenCmtKnowledgeProverInput> input;	// Contains h, c, x, r.
	biginteger alpha, beta; // random values used in the protocol.

	/**
	* Checks the validity of the given soundness parameter.
	* @return true if the soundness parameter is valid; false, otherwise.
	*/
	bool checkSoundnessParam() {
		return (mp::pow(biginteger(2), t) > dlog->getOrder());
	}
	/**
	* Checks if the given challenge length is equal to the soundness parameter.
	*/
	bool checkChallengeLength(int challenge_size) {
		// if the challenge's length is equal to t, return true. else, return false.
		return (challenge_size == (t / 8) ? true : false);
	}
public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaPedersenCmtKnowledgeProverComputation(shared_ptr<DlogGroup> dlog, int t, std::mt19937 random) {
		this->dlog = dlog;
		this->t = t;
		// check the soundness validity.
		if (!checkSoundnessParam()) 
			throw invalid_argument ("soundness parameter t does not satisfy 2^t<q");
		this->random = random;
	}
	/**
	* Returns the soundness parameter for this Sigma protocol.
	*/
	int getSoundnessParam() override { return t; };

	/**
	* Computes the first message of the protocol.<p>
	* "SAMPLE random values alpha, beta <- Zq<p>
	*  COMPUTE a = (h^alpha)*(g^beta)".
	* @return the computed message
	*/
	shared_ptr<SigmaProtocolMsg> computeFirstMsg(shared_ptr<SigmaProverInput> in) override;

	/**
	* Computes the second message of the protocol.<p>
	* "COMPUTE u = alpha + ex mod q and v = beta + er mod q".
	* @param challenge
	* @return the computed message.
	* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
	*/
	shared_ptr<SigmaProtocolMsg> computeSecondMsg(byte* challenge, int challenge_size) override;


	/**
	* Returns the simulator that matches this sigma protocol prover.
	* @return SigmaDlogSimulator
	*/
	shared_ptr<SigmaSimulator> getSimulator() override {
		return make_shared<SigmaPedersenCmtKnowledgeSimulator>(dlog, t, random);
	};

};


/**
* Concrete implementation of Sigma Protocol verifier computation. <p>
* This protocol is used for a committer to prove that the value committed to in the 
* commitment (h, c) is x.<p>
* The pseudo code of this protocol can be found in Protocol 1.4 of pseudo codes document at 
* {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class SigmaPedersenCmtKnowledgeVerifierComputation : public SigmaVerifierComputation, public DlogBasedSigma {
	/*
	This class computes the following calculations:
	SAMPLE a random challenge  e <- {0, 1}^t
	ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e.
	*/
private:
	shared_ptr<DlogGroup> dlog;							// Underlying DlogGroup.
	int t; 									//Soundness parameter in BITS.
	shared_ptr<byte> e;	//The challenge.
	int eSize;
	mt19937 random;
	/**
	* Checks the validity of the given soundness parameter.
	*/
	bool checkSoundnessParam() {
		return (mp::pow(biginteger(2), t) > dlog->getOrder());
	}

public:
	/**
	* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
	* @param dlog
	* @param t Soundness parameter in BITS.
	* @param random
	*/
	SigmaPedersenCmtKnowledgeVerifierComputation(shared_ptr<DlogGroup> dlog, int t, mt19937 random) {
		if (!dlog->validateGroup())
			throw InvalidDlogGroupException("invalide dlog");
		this->dlog = dlog;
		this->t = t;
		// check the soundness validity.
		if (!checkSoundnessParam()) 
			throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
		this->random = random;
	};
	/**
	* Returns the soundness parameter for this Sigma protocol.
	* @return t soundness parameter
	*/
	int getSoundnessParam() override { return t; };
	/**
	* Samples the challenge for this protocol.<p>
	* 	"SAMPLE a random challenge e<-{0,1}^t".
	*/
	void sampleChallenge() override;
	/**
	* Sets the given challenge.
	* @param challenge
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
	* Computes the varification of the protocol.<p>
	* 	"ACC IFF VALID_PARAMS(G,q,g)=TRUE AND h in G AND h^u*g^v=a*c^e".
	* @param input MUST be an instance of SigmaPedersenCTKnowledgeCommonInput.
	* @param a first message from prover
	* @param z second message from prover
	* @return true if the proof has been verified; false, otherwise.
	*/
	bool verify(shared_ptr<SigmaCommonInput> input, shared_ptr<SigmaProtocolMsg> a, 
		shared_ptr<SigmaProtocolMsg> z) override;


};

