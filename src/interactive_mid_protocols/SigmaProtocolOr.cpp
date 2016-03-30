#include "../include/interactive_mid_protocols/SigmaProtocolOr.hpp"


/*********************************/
/*   SigmaORMultipleProverComputation     */
/*********************************/

SigmaORMultipleProverComputation::SigmaORMultipleProverComputation(
	map<int, SigmaProverComputation *> provers, map<int, SigmaSimulator *> simulators, int t,
	mt19937 random) {
	
	// if the given t is different from one of the underlying object's t values, throw exception.
	for (auto& kv : provers) {
		if (t != kv.second->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying provers objects.");
	}
	for (auto& kv : simulators) {
		if (t != kv.second->getSoundnessParam())
			throw invalid_argument("the given t does not equal to one of the t values in the underlying simulators objects.");
	}
	this->provers = provers;
	k = provers.size();
	this->simulators = simulators;
	len = k + simulators.size();
	this->t = t;
	this->random = random;
	// Initialize the field GF2E with a random irreducible polynomial with degree t.
	int randomNum = random();
	NTL_NAMESPACE::GF2X irredPoly = NTL_NAMESPACE::BuildSparseIrred_GF2X(t);

	// init the field with the newly generated polynomial.
	NTL_NAMESPACE::GF2E::init(irredPoly);

	////Sets the seed to the random calculations.
	NTL_NAMESPACE::ZZ seed;
	seed = randomNum;
	NTL_NAMESPACE::SetSeed(seed);
}