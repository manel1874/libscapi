#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalPrivateKey.hpp"

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalPrivateKeySimulator::simulate(SigmaCommonInput* input, vector<byte> challenge) {
	auto elGamalInput = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (elGamalInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	//Convert the input to match the required SigmaDlogSimulator's input.
	SigmaDlogCommonInput * dlogInput = new SigmaDlogCommonInput(elGamalInput->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> dlogInputP(dlogInput);

	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(dlogInputP.get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalPrivateKeyCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalPrivateKeySimulator::simulate(SigmaCommonInput* input) {
	auto elGamalInput = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (elGamalInput == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	//Convert the input to match the required SigmaDlogSimulator's input.
	SigmaDlogCommonInput * dlogInput = new SigmaDlogCommonInput(elGamalInput->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> dlogInputP(dlogInput);

	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(dlogInputP.get());
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaElGamalPrivateKeyProverComputation::SigmaElGamalPrivateKeyProverComputation(shared_ptr<DlogGroup> dlog, int t) : sigmaDlog(dlog, t) {
	this->dlog = dlog;
	this->t = t;
	this->random = get_seeded_random();
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaElGamalPrivateKeyProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalPrivateKeyProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> input){
	auto in = dynamic_pointer_cast<SigmaElGamalPrivateKeyProverInput>(input);
	
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyProverInput");
	}
	
	//Create an input object to the underlying sigma dlog prover.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(make_shared<SigmaDlogProverInput>(dynamic_pointer_cast<SigmaElGamalPrivateKeyCommonInput>(in->getCommonInput())->getPublicKey().getH(), in->getPrivateKey().getX()));

}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalPrivateKeyProverComputation::computeSecondMsg(vector<byte> challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);

}

/**
* Verifies the proof.
* @param z second message from prover
* @param input MUST be an instance of SigmaElGamalPrivateKeyCommonInput.
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalPrivateKeyCommonInput.
* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaGroupElementMsg
* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
*/
bool SigmaElGamalPrivateKeyVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto in = dynamic_cast<SigmaElGamalPrivateKeyCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalPrivateKeyCommonInput");
	}
	
	//Create an input object to the underlying sigma dlog verifier.
	SigmaDlogCommonInput* underlyingInput = new SigmaDlogCommonInput(in->getPublicKey().getH());
	unique_ptr<SigmaDlogCommonInput> inputP(underlyingInput);

	return sigmaDlog.verify(inputP.get(), a, z);
}