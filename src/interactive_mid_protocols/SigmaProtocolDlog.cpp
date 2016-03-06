#include "../../include/interactive_mid_protocols/SigmaProtocolDlog.hpp"

bool check_soundness(int t, shared_ptr<DlogGroup> dlog) {
	// if soundness parameter does not satisfy 2^t<q, return false.
	biginteger soundness = mp::pow(biginteger(2), t);
	biginteger q = dlog->getOrder();
	return (soundness < q);
}

/***************************************/
/*   SigmaDlogSimulator                */
/***************************************/

SigmaDlogSimulator::SigmaDlogSimulator(shared_ptr<DlogGroup> dlog, int t, std::mt19937 random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q. q=" +
			(string)dlog->getOrder() + " t=" + to_string(t) + "\n");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

shared_ptr<SigmaSimulatorOutput> SigmaDlogSimulator::simulate(shared_ptr<SigmaCommonInput> input,
	shared_ptr<byte> challenge, int challenge_size) {
	//check the challenge validity.
	if (!checkChallengeLength(challenge, challenge_size))
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");
	SigmaDlogCommonInput* dlogInput = (SigmaDlogCommonInput*)input.get();

	// SAMPLE a random z <- Zq
	biginteger z = getRandomInRange(0, qMinusOne, random);

	// COMPUTE a = g^z*h^(-e)  (where -e here means -e mod q)
	auto gToZ = dlog->exponentiate(dlog->getGenerator(), z);
	biginteger e = decodeBigInteger(challenge.get(), challenge_size);
	biginteger minusE = dlog->getOrder() - e;
	auto hToE = dlog->exponentiate(dlogInput->getH(), minusE);
	auto a = dlog->multiplyGroupElements(gToZ, hToE);

	// OUTPUT (a,e,eSize,z).
	auto SigmaGEMsg = make_shared<SigmaGroupElementMsg>(a->generateSendableData());
	auto SigmaBMsg = make_shared<SigmaBIMsg>(z);
	return make_shared<SigmaDlogSimulatorOutput>(SigmaGEMsg, challenge, challenge_size, SigmaBMsg);
}

shared_ptr<SigmaSimulatorOutput> SigmaDlogSimulator::simulate(
	shared_ptr<SigmaCommonInput> input) {
	// create a new byte array of size t/8, to get the required byte size.
	std::shared_ptr<byte> e(new byte[t/8], std::default_delete<byte[]>());
	if (!RAND_bytes(e.get(), t / 8)) // fill the byte array with random values.
		throw runtime_error("key generation failed");

	// call the other simulate function with the given input and the sampled e.
	return simulate(input, e, t/8);
}

bool SigmaDlogSimulator::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogProverComputation        */
/***************************************/

SigmaDlogProverComputation::SigmaDlogProverComputation(shared_ptr<DlogGroup> dlog,
	int t, std::mt19937 random) {
	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
	qMinusOne = dlog->getOrder() - 1;
}

shared_ptr<SigmaProtocolMsg> SigmaDlogProverComputation::computeFirstMsg(shared_ptr<SigmaProverInput> input) {
	this->input = shared_ptr<SigmaDlogProverInput>((SigmaDlogProverInput*)input.get());
	// sample random r in Zq
	r = getRandomInRange(0, qMinusOne, random);
	// compute a = g^r.
	auto a = dlog->exponentiate(dlog->getGenerator(), r);
	auto x = a->generateSendableData();
	// create and return SigmaGroupElementMsg with a.
	auto xz = dynamic_pointer_cast<ZpElementSendableData>(x);
	return make_shared<SigmaGroupElementMsg>(x);

}

shared_ptr<SigmaProtocolMsg> SigmaDlogProverComputation::computeSecondMsg(byte* challenge,
	int challenge_size) {
	if (!checkChallengeLength(challenge, challenge_size)) // check the challenge validity.
		throw CheatAttemptException(
			"the length of the given challenge is different from the soundness parameter");

	// compute z = (r+ew) mod q
	biginteger q = dlog->getOrder();
	biginteger e = decodeBigInteger(challenge, challenge_size);
	biginteger ew = (e * input->getW()) % q;
	biginteger z = (r + ew) % q;
	
	// create and return SigmaBIMsg with z
	return make_shared<SigmaBIMsg>(z);
}

bool SigmaDlogProverComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}

/***************************************/
/*   SigmaDlogVerifierComputation      */
/***************************************/

SigmaDlogVerifierComputation::SigmaDlogVerifierComputation(shared_ptr<DlogGroup> dlog,
	int t, std::mt19937 random) {
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("invalid dlog");

	this->dlog = dlog;
	this->t = t;
	if (!checkSoundnessParam()) // check the soundness validity.
		throw invalid_argument("soundness parameter t does not satisfy 2^t<q");
	this->random = random;
}

void SigmaDlogVerifierComputation::sampleChallenge() {
	biginteger e_number = getRandomInRange(0, mp::pow(biginteger(2), t) - 1, random);
	cout << "sampled challenge between 0 and: " << mp::pow(biginteger(2), t)-1 << 
		" got: " << e_number << endl;
	eSize = bytesCount(e_number);
	// create a new byte array of size t/8, to get the required byte size.
	e = std::shared_ptr<byte>(new byte[eSize], std::default_delete<byte[]>());
	encodeBigInteger(e_number, e.get(), eSize);
}

bool SigmaDlogVerifierComputation::verify(shared_ptr<SigmaCommonInput> input, 
	shared_ptr<SigmaProtocolMsg> a, shared_ptr<SigmaProtocolMsg> z) {
	auto cInput = std::dynamic_pointer_cast<SigmaDlogCommonInput>(input);
	if (!cInput)
		throw invalid_argument("input to Dlog verifier should always be instance of SigmaDlogCommonInput");
	bool verified = true;
	auto firstMsg = std::dynamic_pointer_cast<SigmaGroupElementMsg>(a);
	if (!firstMsg)
		throw invalid_argument("first message to Dlog verifier should always be instance of SigmaGroupElementMsg");
	auto exponent = std::dynamic_pointer_cast<SigmaBIMsg>(z);
	if (!exponent)
		throw invalid_argument("second message to Dlog verifier should always be instance of SigmaBIMsg");

	auto aElement = dlog->reconstructElement(true, firstMsg->getElement());

	// get the h from the input and verify that it is in the Dlog Group.
	auto h = cInput->getH();
	// if h is not member in the group, set verified to false.
	verified = verified && dlog->isMember(h);

	// compute g^z (left size of the verify equation).
	auto left = dlog->exponentiate(dlog->getGenerator(), exponent->getMsg());

	// compute a*h^e (right side of the verify equation).
	biginteger eBI = decodeBigInteger(e.get(), eSize); 	// convert e to biginteger.
	auto hToe = dlog->exponentiate(h, eBI); // calculate h^e.

	// calculate a*h^e.
	auto right = dlog->multiplyGroupElements(aElement, hToe);

	// if left and right sides of the equation are not equal, set verified to false.
	verified = verified && (*left==*right);

	// return true if all checks returned true; false, otherwise.
	return verified;
}

bool SigmaDlogVerifierComputation::checkSoundnessParam() {
	return check_soundness(t, dlog);
}