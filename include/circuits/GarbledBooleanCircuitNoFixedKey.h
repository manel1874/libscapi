#pragma once
#include "GarbledBooleanCircuit.h"
class GarbledBooleanCircuitNoFixedKey :
	public GarbledBooleanCircuit
{
public:
	GarbledBooleanCircuitNoFixedKey();
	virtual ~GarbledBooleanCircuitNoFixedKey();

	int getGarbledTableSize() override;
};

