#include "../../include/interactive_mid_protocols/SigmaProtocolCramerShoupEncryptedValue.hpp"

/**
* Sets the ciphertext, public key and the encrypted element.
* @param cipher ciphertext the output of the encryption scheme on the encrypted element.
* @param publicKey used to encrypt.
* @param x encrypted element.
*/
SigmaCramerShoupEncryptedValueCommonInput::SigmaCramerShoupEncryptedValueCommonInput(CramerShoupOnGroupElementCiphertext cipher, CramerShoupPublicKey publicKey, shared_ptr<GroupElement> x)
	:publicKey(publicKey), cipher(cipher) {
	this->x = x;
}

/**
* Sets the ciphertext, public key, the encrypted element and the random value used to encrypt x.
* @param cipher ciphertext the output of the encryption scheme on the encrypted element.
* @param publicKey used to encrypt.
* @param x encrypted element.
* @param r random value used to encrypt x.
*/
SigmaCramerShoupEncryptedValueProverInput::SigmaCramerShoupEncryptedValueProverInput(CramerShoupOnGroupElementCiphertext cipher, CramerShoupPublicKey pubKey, shared_ptr<GroupElement> x, biginteger r) {
	input = make_shared<SigmaCramerShoupEncryptedValueCommonInput>(cipher, pubKey, x);
	this->r = r;
}

/**
* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
* @param dlog DlogGroup used in CramerShoup encryption scheme.
* @param hash CryptographicHash used in CramerShoup encryption scheme.
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaCramerShoupEncryptedValueSimulator::SigmaCramerShoupEncryptedValueSimulator(shared_ptr<DlogGroup> dlog, shared_ptr<CryptographicHash> hash, int t) : dhSim(dlog, t) {

	this->dlog = dlog;
	this->hash = hash;
}

/**
* Computes the simulator computation with the given challenge.
* @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
* @param challenge
* @return the output of the computation - (a, e, z).
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaCramerShoupEncryptedValueSimulator::simulate(SigmaCommonInput* input, vector<byte> challenge) {

	//Delegates the computation to the underlying Sigma DHExtended simulator.
	return dhSim.simulate(checkAndCreateUnderlyingInput(input).get(), challenge);

}

/**
* Computes the simulator computation with a randomly chosen challenge.
* @param input MUST be an instance of SigmaCramerShoupEncryptedValueInput.
* @return the output of the computation - (a, e, z).
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaSimulatorOutput> SigmaCramerShoupEncryptedValueSimulator::simulate(SigmaCommonInput* input) {
	
	//Delegates the computation to the underlying Sigma DHExtended simulator.
	return dhSim.simulate(checkAndCreateUnderlyingInput(input).get());

}

shared_ptr<SigmaDHExtendedCommonInput> SigmaCramerShoupEncryptedValueSimulator::checkAndCreateUnderlyingInput(SigmaCommonInput* in) {
	auto input = dynamic_cast<SigmaCramerShoupEncryptedValueCommonInput*>(in);
	if (input == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaCramerShoupEncryptedValueCommonInput");
	}

	//Gets the input values.
	auto publicKey = input->getPublicKey();
	auto cipher = input->getCipher();
	auto x = input->getX();

	//Prepare the input for the underlying SigmaDHExtendedSimulator.
	vector<shared_ptr<GroupElement>> gArray,hArray;

	//Converts the given input to the necessary input to the underlying SigmaDHExtendedSimulator.
	//(g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)

	//add the input for the gArray:
	gArray.push_back(publicKey.getGenerator1()); //add g1 = g1.
	gArray.push_back(publicKey.getGenerator2()); //add g2 = g2.
	gArray.push_back(publicKey.getH());			 //add g3 = h.

	//Compute w = H(u1,u2,e).
	biginteger w = calcW(cipher.getU1(), cipher.getU2(), cipher.getE()) % dlog->getOrder();
	//Compute cd^w. such that w = H(u1,u2,e).
	auto dToW = dlog->exponentiate(publicKey.getD().get(), w);
	auto g4 = dlog->multiplyGroupElements(publicKey.getC().get(), dToW.get());
	gArray.push_back(g4);		   				   //add g4 = cd^w.

	//add the input for the hArray:
	hArray.push_back(cipher.getU1());			   //add h1 = u1.
	hArray.push_back(cipher.getU2());			   //add h2 = u2.
	//Compute e/x = e*x^(-1)
	auto xInverse = dlog->getInverse(x.get());
	auto h3 = dlog->multiplyGroupElements(cipher.getE().get(), xInverse.get());
	hArray.push_back(h3);			   			   //add h3 = e/x.
	hArray.push_back(cipher.getV());			   //add h4 = v.

	//Create an input object to the underlying sigma DHExtended simulator.
	return make_shared<SigmaDHExtendedCommonInput>(gArray, hArray);
}

/**
* Receives three byte arrays and calculates the hash function on their concatenation.
* @param u1ToByteArray
* @param u2ToByteArray
* @param eToByteArray
* @return the result of hash(u1ToByteArray+u2ToByteArray+eToByteArray) as BigInteger.
*/
biginteger SigmaCramerShoupEncryptedValueSimulator::calcW(shared_ptr<GroupElement> u1, shared_ptr<GroupElement> u2, shared_ptr<GroupElement> e) {

	auto u1ToByteArray = dlog->mapAnyGroupElementToByteArray(u1.get());
	auto u2ToByteArray = dlog->mapAnyGroupElementToByteArray(u2.get());
	auto eToByteArray = dlog->mapAnyGroupElementToByteArray(e.get());

	//Concatenates u1, u2 and e into u1.
	u1ToByteArray.insert(u1ToByteArray.end(), u2ToByteArray.begin(), u2ToByteArray.end());
	u1ToByteArray.insert(u1ToByteArray.end(), eToByteArray.begin(), eToByteArray.end());

	//Calculates the hash of msgToHash.

	//Calls the update function in the Hash interface.
	hash->update(u1ToByteArray, 0, u1ToByteArray.size());

	//Gets the result of hashing the updated input.
	vector<byte> alpha;
	hash->hashFinal(alpha, 0);

	return decodeBigInteger(alpha.data(), alpha.size());
}

/**
* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
* @param dlog DlogGroup used in CramerShoup encryption scheme.
* @param hash CryptographicHash used in CramerShoup encryption scheme.
* @param t Soundness parameter in BITS.
* @param random
*/
SigmaCramerShoupEncryptedValueProverComputation::SigmaCramerShoupEncryptedValueProverComputation(shared_ptr<DlogGroup> dlog, shared_ptr<CryptographicHash> hash, int t) 
	: sigmaDH(dlog, t) {

	this->dlog = dlog;
	this->hash = hash;
	this->t = t;
	this->random = get_seeded_random();
}

biginteger SigmaCramerShoupEncryptedValueProverComputation::calcW(shared_ptr<GroupElement> u1, shared_ptr<GroupElement> u2, shared_ptr<GroupElement> e) {

	auto u1ToByteArray = dlog->mapAnyGroupElementToByteArray(u1.get());
	auto u2ToByteArray = dlog->mapAnyGroupElementToByteArray(u2.get());
	auto eToByteArray = dlog->mapAnyGroupElementToByteArray(e.get());

	//Concatenates u1, u2 and e into u1.
	u1ToByteArray.insert(u1ToByteArray.end(), u2ToByteArray.begin(), u2ToByteArray.end());
	u1ToByteArray.insert(u1ToByteArray.end(), eToByteArray.begin(), eToByteArray.end());

	//Calculates the hash of msgToHash.

	//Calls the update function in the Hash interface.
	hash->update(u1ToByteArray, 0, u1ToByteArray.size());

	//Gets the result of hashing the updated input.
	vector<byte> alpha;
	hash->hashFinal(alpha, 0);

	return decodeBigInteger(alpha.data(), alpha.size());
}

/**
* Computes the first message of the protocol.
* @param input MUST be an instance of SigmaCramerShoupEncryptedValueProverInput.
* @return the computed message
* @throws IllegalArgumentException if input is not the expected.
*/
shared_ptr<SigmaProtocolMsg> SigmaCramerShoupEncryptedValueProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> input) {
	auto in = dynamic_pointer_cast<SigmaCramerShoupEncryptedValueProverInput>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaCramerShoupEncryptedValueProverInput");
	}

	//Gets the input values.
	auto params = dynamic_pointer_cast<SigmaCramerShoupEncryptedValueCommonInput>(in->getCommonInput());
	auto publicKey = params->getPublicKey();
	auto cipher = params->getCipher();
	auto x = params->getX();
	biginteger r = in->getR();

	//Prepare the input for the underlying SigmaDHExtendedProver.
	vector<shared_ptr<GroupElement>> gArray, hArray;

	//Converts the given input to the necessary input to the underlying SigmaDHExtendedProver.
	//(g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)

	//add the input for the gArray:
	gArray.push_back(publicKey.getGenerator1()); //add g1 = g1.
	gArray.push_back(publicKey.getGenerator2()); //add g2 = g2.
	gArray.push_back(publicKey.getH());			 //add g3 = h.

	//Compute w = H(u1,u2,e).
	biginteger w = calcW(cipher.getU1(), cipher.getU2(), cipher.getE()) % dlog->getOrder();
	//Compute cd^w. such that w = H(u1,u2,e).
	auto dToW = dlog->exponentiate(publicKey.getD().get(), w);
	auto g4 = dlog->multiplyGroupElements(publicKey.getC().get(), dToW.get());
	gArray.push_back(g4);		   				   //add g4 = cd^w.

	//add the input for the hArray:
	hArray.push_back(cipher.getU1());			   //add h1 = u1.
	hArray.push_back(cipher.getU2());			   //add h2 = u2.
	//Compute e/x = e*x^(-1)
	auto xInverse = dlog->getInverse(x.get());
	auto h3 = dlog->multiplyGroupElements(cipher.getE().get(), xInverse.get());
	hArray.push_back(h3);			   			   //add h3 = e/x.
	hArray.push_back(cipher.getV());			   //add h4 = v.

	//Creates an input object to the underlying sigma DHExtended prover.
	//Delegates the computation to the underlying Sigma DHExtended prover.
	return sigmaDH.computeFirstMsg(make_shared<SigmaDHExtendedProverInput>(gArray, hArray, r));
}

/**
* Computes the second message of the protocol.
* @param challenge
* @return the computed message.
* @throws CheatAttemptException if the received challenge's length is not equal to the soundness parameter.
*/
shared_ptr<SigmaProtocolMsg> SigmaCramerShoupEncryptedValueProverComputation::computeSecondMsg(vector<byte> challenge) {
	//Delegates the computation to the underlying Sigma DHExtended prover.
	return sigmaDH.computeSecondMsg(challenge);
}

/**
* Constructor that gets the underlying DlogGroup, CryptographicHash, soundness parameter and SecureRandom.
* @param dlog DlogGroup used in CramerShoup encryption scheme.
* @param hash CryptographicHash used in CramerShoup encryption scheme.
* @param t Soundness parameter in BITS.
* @param random
* @throws InvalidDlogGroupException if the given dlog is invalid.
*/
SigmaCramerShoupEncryptedValueVerifierComputation::SigmaCramerShoupEncryptedValueVerifierComputation(shared_ptr<DlogGroup> dlog, shared_ptr<CryptographicHash> hash, int t)
	: sigmaDH(dlog, t) {

	this->dlog = dlog;
	this->hash = hash;
}

biginteger SigmaCramerShoupEncryptedValueVerifierComputation::calcW(shared_ptr<GroupElement> u1, shared_ptr<GroupElement> u2, shared_ptr<GroupElement> e){

	auto u1ToByteArray = dlog->mapAnyGroupElementToByteArray(u1.get());
	auto u2ToByteArray = dlog->mapAnyGroupElementToByteArray(u2.get());
	auto eToByteArray = dlog->mapAnyGroupElementToByteArray(e.get());

	//Concatenates u1, u2 and e into u1.
	u1ToByteArray.insert(u1ToByteArray.end(), u2ToByteArray.begin(), u2ToByteArray.end());
	u1ToByteArray.insert(u1ToByteArray.end(), eToByteArray.begin(), eToByteArray.end());

	//Calculates the hash of msgToHash.

	//Calls the update function in the Hash interface.
	hash->update(u1ToByteArray, 0, u1ToByteArray.size());

	//Gets the result of hashing the updated input.
	vector<byte> alpha;
	hash->hashFinal(alpha, 0);

	return decodeBigInteger(alpha.data(), alpha.size());
}

/**
* Verifies the proof.
* @param input MUST be an instance of SigmaCramerShoupEncryptedValueCommonInput.
* @param z second message from prover
* @return true if the proof has been verified; false, otherwise.
* @throws IllegalArgumentException if input is not the expected.
* @throws IllegalArgumentException if the first message of the prover is not an instance of SigmaDHExtendedMsg
* @throws IllegalArgumentException if the second message of the prover is not an instance of SigmaBIMsg
*/
bool SigmaCramerShoupEncryptedValueVerifierComputation::verify(SigmaCommonInput* input, SigmaProtocolMsg* a, SigmaProtocolMsg* z) {
	auto in = dynamic_cast<SigmaCramerShoupEncryptedValueCommonInput*>(input);
	if (in == NULL) {
		throw invalid_argument("the given input must be an instance of SigmaCramerShoupEncryptedValueCommonInput");
	}

	//Gets the input values.
	auto publicKey = in->getPublicKey();
	auto cipher = in->getCipher();
	auto x = in->getX();

	//Prepare the input for the underlying SigmaDHExtendedVerifier.
	vector<shared_ptr<GroupElement>> gArray, hArray;

	//Converts the given input to the necessary input to the underlying SigmaDHExtendedVerifier.
	//(g1,g2,g3,g4,h1,h2,h3,h4) = (g1,g2,h,cd^w,u1,u2,e/x,v)

	//add the input for the gArray:
	gArray.push_back(publicKey.getGenerator1()); //add g1 = g1.
	gArray.push_back(publicKey.getGenerator2()); //add g2 = g2.
	gArray.push_back(publicKey.getH());		   //add g3 = h.

	//Compute w = H(u1,u2,e).
	biginteger w = calcW(cipher.getU1(), cipher.getU2(), cipher.getE()) % dlog->getOrder();
	//Compute cd^w. such that w = H(u1,u2,e).
	auto dToW = dlog->exponentiate(publicKey.getD().get(), w);
	auto g4 = dlog->multiplyGroupElements(publicKey.getC().get(), dToW.get());
	gArray.push_back(g4);		   				   //add g4 = cd^w.

	 //add the input for the hArray:
	hArray.push_back(cipher.getU1());			   //add h1 = u1.
	hArray.push_back(cipher.getU2());			   //add h2 = u2.
	//Compute e/x = e*x^(-1)
	auto xInverse = dlog->getInverse(x.get());
	auto h3 = dlog->multiplyGroupElements(cipher.getE().get(), xInverse.get());
	hArray.push_back(h3);			   			   //add h3 = e/x.
	hArray.push_back(cipher.getV());			   //add h4 = v.

	//Create an input object to the underlying sigma DHExtended verifier.
	//Delegates to the underlying Sigma DHExtended verifier.
	return sigmaDH.verify(make_shared<SigmaDHExtendedCommonInput>(gArray, hArray).get(), a, z);
}