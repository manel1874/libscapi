//#include "stdafx.h"
#include "../../include/circuits/GarbledBooleanCircuitNoFixedKey.h"


GarbledBooleanCircuitNoFixedKey::GarbledBooleanCircuitNoFixedKey()
{
}


GarbledBooleanCircuitNoFixedKey::~GarbledBooleanCircuitNoFixedKey()
{
}


int GarbledBooleanCircuitNoFixedKey::getGarbledTableSize()
{

	if (isNonXorOutputsRequired == true) {
		return sizeof(block) * ((numberOfGates - numOfXorGates - numOfNotGates) * 2 + 2 * numberOfOutputs);
	}
	else {
		return sizeof(block) * (numberOfGates - numOfXorGates - numOfNotGates) * 2;
	}


}
