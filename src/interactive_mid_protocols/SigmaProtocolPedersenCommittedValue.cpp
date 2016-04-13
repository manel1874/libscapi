#include "../../include/interactive_mid_protocols/SigmaProtocolPedersenCommittedValue.hpp"

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaPedersenCommittedValueSimulator::SigmaPedersenCommittedValueSimulator(shared_ptr<DlogGroup> dlog, int t, mt19937 random) : dlogSim(dlog, t, random) {

	//Creates the underlying SigmaDlogSimulator object with the given parameters.
	this->dlog = dlog.get();
}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCommittedValueSimulator::simulate(SigmaCommonInput* input, vector<byte> challenge) {
	
	//Delegate the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(&convertInput(input), challenge);

}

shared_ptr<SigmaSimulatorOutput> SigmaPedersenCommittedValueSimulator::simulate(SigmaCommonInput* input) {
	//Delegate the computation to the underlying Sigma Dlog simulator.
	return dlogSim.simulate(&convertInput(input));
}

SigmaDlogCommonInput SigmaPedersenCommittedValueSimulator::convertInput(SigmaCommonInput* in) {
	auto params = dynamic_cast<SigmaPedersenCommittedValueCommonInput*>(in);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}
	
	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - params->getX();
	auto hToX = dlog->exponentiate(params->getH().get(), minusX);
	auto c = params->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	//Create and return the input instance with the computes h'.
	SigmaDlogCommonInput underlyingInput(hTag);
	return underlyingInput;
}

/**
* Constructor that gets the underlying DlogGroup, soundness parameter and SecureRandom.
* @param dlog
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaPedersenCommittedValueProverComputation::SigmaPedersenCommittedValueProverComputation(shared_ptr<DlogGroup> dlog, int t, mt19937 random) : sigmaDlog(dlog, t, random) {

	this->dlog = dlog;
	this->t = t;
	this->random = random;
}

/**
* Returns the soundness parameter for this Sigma protocol.
* @return t soundness parameter
*/
int SigmaPedersenCommittedValueProverComputation::getSoundnessParam() {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.getSoundnessParam();
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCommittedValueProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> input)  {
	//Converts the input to the underlying prover.
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeFirstMsg(convertInput(input.get()));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaPedersenCommittedValueProverComputation::computeSecondMsg(vector<byte> challenge) {
	//Delegates the computation to the underlying Sigma Dlog prover.
	return sigmaDlog.computeSecondMsg(challenge);

}

/**
* Converts the input for the underlying prover computation.
* @param input MUST be an instance of SigmaPedersenCommittedValueProverInput.
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueProverInput.
*/
shared_ptr<SigmaDlogProverInput> SigmaPedersenCommittedValueProverComputation::convertInput(SigmaProverInput* in) {
	auto params = dynamic_cast<SigmaPedersenCommittedValueProverInput*>(in);

	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (params == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueProverInput");
	}

	auto commonParams = dynamic_pointer_cast<SigmaPedersenCommittedValueCommonInput>(params->getCommonInput());
	//If the given input is not an instance of SigmaPedersenCommittedValueCommonInput throw exception
	if (commonParams == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}

	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - commonParams->getX();
	auto hToX = dlog->exponentiate(commonParams->getH().get(), minusX);
	auto c = commonParams->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	//Create and return the input instance with the computes h'.
	return make_shared<SigmaDlogProverInput>(hTag, params->getR());
}

/**
* Sets the input for this Sigma protocol.
* @param input MUST be an instance of SigmaPedersenCommittedValueCommonInput.
* @throws IllegalArgumentException if input is not an instance of SigmaPedersenCommittedValueCommonInput.
*/
shared_ptr<SigmaDlogCommonInput> SigmaPedersenCommittedValueVerifierComputation::convertInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaPedersenCommittedValueCommonInput*>(in);
	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaPedersenCommittedValueCommonInput");
	}
	
	//Convert the input to the underlying Dlog prover. h' = c*h^(-x).
	biginteger minusX = dlog->getOrder() - input->getX();
	auto hToX = dlog->exponentiate(input->getH().get(), minusX);
	auto c = input->getCommitment();
	auto hTag = dlog->multiplyGroupElements(c.get(), hToX.get());

	return make_shared<SigmaDlogCommonInput>(hTag);

}