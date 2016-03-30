#pragma once

#include <string>

class GarbledBooleanCircuit;


class GarbledCircuitFactory
{

public:
	enum CircuitType {
		FIXED_KEY_FREE_XOR_HALF_GATES,
		FIXED_KEY_FREE_XOR_ROW_REDUCTION,
		FIXED_KEY_FREE_XOR_STANDARD,
		FIXED_KEY_STANDARD,
		NO_FIXED_KEY_FREE_XOR_HALF_GATES,
		NO_FIXED_KEY_FOUR_TO_TWO
	};

	static GarbledBooleanCircuit* createCircuit(std::string fileName, CircuitType type, bool isNonXorOutputsRequired = false);

};
