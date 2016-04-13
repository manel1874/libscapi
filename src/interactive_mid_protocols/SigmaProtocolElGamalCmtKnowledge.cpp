#include "../../include/interactive_mid_protocols/SigmaProtocolElGamalCmtKnowledge.hpp"

shared_ptr<SigmaDlogCommonInput> SigmaElGamalCmtKnowledgeSimulator::convertInput(SigmaCommonInput* input) {
	auto params = dynamic_cast<SigmaElGamalCmtKnowledgeCommonInput*>(input);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeCommonInput");
	}

	//Convert the input to match the required SigmaDlogSimulator's input.
	auto h = params->getPublicKey().getH();
	return make_shared<SigmaDlogCommonInput>(h);
}

/**
* Computes the simulator computation.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCmtKnowledgeSimulator::simulate(SigmaCommonInput* input, vector<byte> challenge) {
	//Converts the input to an input object of the underlying simulator.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return dlogSim.simulate(convertInput(input).get(), challenge);

}

/**
* Computes the simulator computation.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if the given input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaSimulatorOutput> SigmaElGamalCmtKnowledgeSimulator::simulate(SigmaCommonInput* input){
	//Converts the input to an input object of the underlying simulator.
	//Delegates the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(convertInput(input).get());
}

/**
* Converts the input for this Sigma protocol to the underlying protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
*/
shared_ptr<SigmaDlogProverInput> SigmaElGamalCmtKnowledgeProverComputation::convertInput(SigmaProverInput* in) {
	auto input = dynamic_cast<SigmaElGamalCmtKnowledgeProverInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeProverInput");
	}
	
	//Create an input object to the underlying sigma dlog prover.
	auto h = (dynamic_pointer_cast<SigmaElGamalCmtKnowledgeCommonInput>(input->getCommonInput()))->getPublicKey().getH();
	return make_shared<SigmaDlogProverInput>(h, input->getW());

}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaElGamalCmtKnowledgeProverComputation::SigmaElGamalCmtKnowledgeProverComputation(shared_ptr<DlogGroup> dlog, int t, mt19937 random) : sigmaDlog(dlog, t, random) {
	this->dlog = dlog;
	this->t = t;
	this->random = random;
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCmtKnowledgeProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> input) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(convertInput(input.get()));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaElGamalCmtKnowledgeProverComputation::computeSecondMsg(vector<byte> challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);
}

/**
* Convert the input for this Sigma protocol to the underlying protocol.
* @param input MUST be an instance of SigmaElGamalCTKnowledgeCommonInput.
* @throws IllegalArgumentException if input is not an instance of SigmaElGamalCTKnowledgeCommonInput.
*/
shared_ptr<SigmaDlogCommonInput> SigmaElGamalCmtKnowledgeVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaElGamalCmtKnowledgeCommonInput*>(in);

	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaElGamalCTKnowledgeCommonInput");
	}
	

	//Create an input object to the underlying sigma dlog prover.
	auto h = input->getPublicKey().getH();

	return make_shared<SigmaDlogCommonInput>(h);

}