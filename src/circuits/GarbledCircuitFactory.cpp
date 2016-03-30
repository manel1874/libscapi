#include "../../include/circuits/GarbledCircuitFactory.hpp"
#include "../../include/circuits/RowReductionGarbledBooleanCircuit.h"
#include "../../include/circuits/StandardGarbledBooleanCircuit.h"
#include "../../include/circuits/FreeXorGarbledBooleanCircuit.h"
#include "../../include/circuits/HalfGatesGarbledBooleanCircuit.h"
#include "../../include/circuits/HalfGatesGarbledBoleanCircuitNoFixedKey.h"
#include "../../include/circuits/FourToTwoGarbledBoleanCircuitNoAssumptions.h"



GarbledBooleanCircuit* GarbledCircuitFactory::createCircuit(std::string fileName, CircuitType type,bool isNonXorOutputsRequired) {

	// create the fitting circuit type
	switch (type) {
	case CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES:
		return new HalfGatesGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_FREE_XOR_ROW_REDUCTION:
		return new RowReductionGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_FREE_XOR_STANDARD:
		return new FreeXorGarbledBooleanCircuit(fileName.c_str(), isNonXorOutputsRequired);

	case CircuitType::FIXED_KEY_STANDARD:
		return new StandardGarbledBooleanCircuit(fileName.c_str());

	case CircuitType::NO_FIXED_KEY_FREE_XOR_HALF_GATES:
		return new HalfGatesGarbledBoleanCircuitNoFixedKey(fileName.c_str());

	case CircuitType::NO_FIXED_KEY_FOUR_TO_TWO:
		return new FourToTwoGarbledBoleanCircuitNoAssumptions(fileName.c_str());

	default:
		throw std::invalid_argument("got unknown circuit type");
		break;
	}

	return nullptr;
}