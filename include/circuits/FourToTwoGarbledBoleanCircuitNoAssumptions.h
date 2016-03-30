#pragma once
#include "GarbledBooleanCircuitNoFixedKey.h"
#include <vector>

/*

*/
class FourToTwoGarbledBoleanCircuitNoAssumptions :
	public GarbledBooleanCircuitNoFixedKey
{
public:
public:
	FourToTwoGarbledBoleanCircuitNoAssumptions();
	FourToTwoGarbledBoleanCircuitNoAssumptions(const char* fileName);
	virtual ~FourToTwoGarbledBoleanCircuitNoAssumptions();

private:

	block* encryptedChunkKeys;//The result of chunk encrypting indexArray.
	block* indexArray;//An array that holds the number 0 to the number of nonXorGates and is calculated in advence.
	//The purpuse of this array is that we can calculate. this array and all the keys of the circuit in advence using ecb mode
	//with one chuck gaining pipelining	


public:

	

	int getGarbledTableSize() override;
	/**
	* This method computes the circuit for the given input singleWiresInputKeys.
	* It returns a the garbled values keys for the output wires. This output can be translated via the translate() method
	* if the translation table is set.
	*/
	void compute(block * singleWiresInputKeys, block * Output) override;

	/**
	* This function behaves exactly as the verify method except the last phase.
	* The verify function verifies that the translation table matches the resulted output garbled values, while this function does not, rather,
	* it returns the resulted output garbled values.
	*
	* In this verify method we compare the garbled table of the circuit with the garbled table that should be created
	* for the xor gates. For the AND gates, since there is randomization and the input keys alone can create the garbled table
	* deterministically, for these gates we compare the 0 garbled wire of the output in the 3 options of compute and calculate the 1-value 
	* for future use.
	*
	* bothWiresInputKeys : both keys for each input wire. This array must be filled with both input keys
	* emptyBothWireOutputKeys :This array will be filled with both output keys during the process of the function. It must be empty.
	*
	* returns : true if the garbled table of this circuit is complied with the given input keys, false otherwise.
	*/
	bool internalVerify(block *bothInputKeys, block *emptyBothWireOutputKeys) override;


protected:

	/*
	* Creates the memory needed for this class in addition to the memory that is allocated by the base class.
	*/
	void createCircuitMemory(const char* fileName, bool isNonXorOutputsRequired = false) override;

private:

	/*
	* This method generates both keys for each wire. Then, creates the garbled table according to those values with the row reduction technique.
	* In the row reduction technique the garbled table of has three encryptions instead of four, the last row is not saved and will be calculated
	* when the compute function will be called.
	* The keys for each wire are not saved. The input keys and the output keys that were created are retuned to the
	* user. The user usually saves these value for later use. The user also gets the generated translation table, which is
	* the signal bits of the output wires.
	*
	* emptyBothInputKeys : An empty block array that will be filled with both input keys generated in garble.
	* emptyBothOutputKeys : An empty block array that will be filled with both output keys generated in garble.
	* emptyTranslationTable : An empty char array that will be filled with 0/1 signal bits that wre choosen in random in this function.
	*/
	void garble(block *emptyBothInputKeys, block *emptyBothOutputKeys, std::vector<byte> emptyTranslationTable, block seed) override;
	

	/*
	* This function inits the keys for all the wires in the circuit and initializes the two aes encryptions (seed and fixedKey as keys). It also choses
	* the input keys at random using the aes with seed. It also creates memory for the translation table.
	*/
	void initAesEncryptionsAndInputKeys(block* emptyBothInputKeys);
};

