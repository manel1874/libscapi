#include "GarbledBooleanCircuit.h"
#include "GarbledGate.h"
#include "Config.h"
#include <ctime>
#include <iostream>
#include <fstream>
#include <sstream>
#include "mmintrin.h"
#include "TedKrovetzAesNiWrapperC.h"

#ifdef _WIN32
#include "StdAfx.h"
#else
#include <string.h>
#include "Compat.h"
#endif

using namespace std;

GarbledBooleanCircuit::GarbledBooleanCircuit(void)
{
}


GarbledBooleanCircuit::~GarbledBooleanCircuit(void)
{

	if(inputIndices != NULL)
		delete[] inputIndices;
	
	if(outputIndices != NULL)
		delete[] outputIndices;

	
	if (garbledGates != NULL){
		delete[] garbledGates;
	}
		

	if(translationTable != NULL)
		delete[] translationTable;

	if (numOfInputsForEachParty != NULL)
		delete[] numOfInputsForEachParty;


	if(garbledTables != NULL)
		_aligned_free(garbledTables);


	if (computedWires != NULL){
		computedWires--;
		_aligned_free(computedWires);
	}

	if(seed != NULL)
		_aligned_free(seed);

	if(fixedKey!= NULL)
		_aligned_free(fixedKey);

	if (aesSeedKey != NULL)
		_aligned_free(aesSeedKey);

	if (aesFixedKey != NULL)
		_aligned_free(aesFixedKey);


}

void GarbledBooleanCircuit::createCircuit(const char* fileName, bool isFreeXor, bool isRowReduction, bool isNonXorOutputsRequired){
	//clock_t start, stop;


	//start = clock();
	this->isFreeXor = isFreeXor;
	this->isRowReduction = isRowReduction;
	this->isNonXorOutputsRequired = isNonXorOutputsRequired;

	

	//init all the variable to either null or 0 for integers.
	lastWireIndex = 0;
	numberOfGates = 0;
	numOfXorGates = 0;	
	numOfNotGates = 0;
	numberOfParties = 0;
	numOfInputsForEachParty = NULL;
	numberOfInputs = 0;
	numberOfOutputs = 0;

	inputIndices = NULL;
	outputIndices = NULL;
	garbledTables = NULL;
	garbledGates = NULL;
	translationTable = NULL;
	garbledWires = NULL;
	computedWires = NULL;
	seed = NULL;
	fixedKey = NULL;
	aesFixedKey = NULL;
	aesSeedKey = NULL;

	//read the file and fill the gates, number of parties, input indices, output indices and so on.
	readCircuitFromFile(fileName);

	seed = (block *)_aligned_malloc(sizeof(block), 16);
	fixedKey = (block *)_aligned_malloc(sizeof(block), 16);
	//Set the fixed key.
	*fixedKey = _mm_set_epi8(36, -100,50, -22, 92, -26, 49, 9,-82 , -86, -51, -96, 98, -20, 29,  -13);

	aesFixedKey = (AES_KEY *)_aligned_malloc(sizeof(AES_KEY), 16);
	aesSeedKey = (AES_KEY *)_aligned_malloc(sizeof(AES_KEY), 16);


	//create the round keys for the fixed key.
	AES_set_encrypt_key((const unsigned char *)fixedKey, 128, aesFixedKey);

	if (isNonXorOutputsRequired){
		computedWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1 + numberOfOutputs), 16);//the wires that have been already computed. It is assumed that when a gate is handled the

		if (computedWires == NULL) {
			cout << "computedWires could not be allocated";
			exit(0);
		}
		memset(computedWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1) + numberOfOutputs);
		computedWires++;

	}
	else
	{
		computedWires = (block *)_aligned_malloc(sizeof(block) * ((lastWireIndex + 1) + 1), 16);//the wires that have been already computed. It is assumed that when a gate is handled the

		if (computedWires == NULL) {
			cout << "computedWires could not be allocated";
			exit(0);
		}
		memset(computedWires, 0, sizeof(block) * ((lastWireIndex + 1) + 1));
		computedWires++;

	}
	
	//allocate memory for the translation table
	translationTable = new unsigned char[numberOfOutputs]; 
}


int* GarbledBooleanCircuit::readInputsFromFile(char* fileName){

	ifstream myfile;
	int numberOfInputs;
	int* inputs = NULL;
	myfile.open (fileName);
	if (myfile.is_open())
	{
		//get the number of inputs
		myfile >> numberOfInputs;//get the number of inputs
		inputs = new int[numberOfInputs];

		//fille the an int array with the bits of the inputs read from the file
		for(int i=0; i<numberOfInputs; i++){
			myfile >> inputs[i];
		}
	}
		
	return inputs;
}



int GarbledBooleanCircuit::binaryTodecimal(int n){
	
	int output = 0;
	int pow = 1;

	//turns the string of the truth table that was taken as a decimal number into a number between 0 and 15 which represents the truth table
	//0 means the truth table of 0000 and 8 means 10 and so on. The functions returns the decimal representation of the thruth table.
	for(int i=0; n > 0; i++) {
		
		if(n % 10 == 1) {
			
			output += pow;
		}
		n /= 10;

		pow = pow*2;
	}
	return output;
}



bool GarbledBooleanCircuit::getIsRowReduction(){
	return isRowReduction;
}


int GarbledBooleanCircuit::getRowTruthTableResult(int i, int j, unsigned char truthTable){

	//get the row of the table starting from 0
	int rowNumber = 2*i + j;

	//return the result of row i,j.
	return truthTable & integerPow(3-rowNumber);
}


int GarbledBooleanCircuit::integerPow(int p) {

	switch( p ) {
      case(0):
		return 1;
	  case(1):
		return 2;
      case(2):
		return 4;
      default:
		return 8;
	
    }

}


void GarbledBooleanCircuit::translate(block *outputKeys, unsigned char* answer){

	
	for(int i=0; i<numberOfOutputs;i++){

		//The answer of i'th position is the signal bit of the XOr between the related translation table location and the related outputKey array position
		answer[i] = getSignalBitOf(outputKeys[i]) ^ translationTable[i];
		
	}

}


unsigned char* GarbledBooleanCircuit::getTranslationTable(){

	return translationTable;
}

void GarbledBooleanCircuit::setTranslationTable(unsigned char* translationTable){

	
	if (this->translationTable != NULL && this->translationTable != translationTable)
		delete[] this->translationTable;

	this->translationTable = translationTable;
}
	

void GarbledBooleanCircuit::setGarbledTables(block* garbledTables){

	if (this->garbledTables != NULL && this->garbledTables != garbledTables)
		_aligned_free(this->garbledTables);

	this->garbledTables = garbledTables;
}



int *GarbledBooleanCircuit::getNumOfInputsForEachParty(){
	return numOfInputsForEachParty;
}



void  GarbledBooleanCircuit::compute(block * singleWiresInputKeys, block * Output)
{
	int nonXorIndex= 0;
	for(int i=0; i<numberOfInputs;i++){

		//get the input keys into the computed wires array
		computedWires[inputIndices[i]] =  singleWiresInputKeys[i];
	}

	int jumpInGarblesTable;//the jump in the garbled table we need to make. 3 for row reduction, as the row reduction has only 3 values in each garbled table
	//and 4 for a regular circuit that holds garbled tables with all 4 values	

	if(isRowReduction){
		jumpInGarblesTable = 3;//every gate only consumes 3 blocks
	}
	else{
		jumpInGarblesTable = 4;//every gate consumes 4 blocks
	}

	for(int i=0; i<numberOfGates; i++){

		if ((garbledGates[i].truthTable == XOR_GATE ||  garbledGates[i].truthTable == XOR_NOT_GATE) && isFreeXor==true){
			//create the output key by xoring the computed keys if the first input wire and the second input wire
			computedWires[garbledGates[i].output] = _mm_xor_si128(computedWires[garbledGates[i].input0], computedWires[garbledGates[i].input1]);
			continue;

		}
		
		else{

			block encryptedKey;
			//get the keys from the already calculated wires
			block A = computedWires[garbledGates[i].input0];
			block B = computedWires[garbledGates[i].input1];

			//Shift left to double A for security (actually the 2 64 bit are shifted and not the whole 128 bit block
			block twoA = _mm_slli_epi64(A,1);
			//Shift right instead of shifting left twice.This is secure since the alignment is broken
			block fourB = _mm_srli_epi64(B,1);

			//Get the signal bits of A and B which are the input keys computed.
			int a = getSignalBitOf(A);
			int b = getSignalBitOf(B);

			//Calc the tweak
			block tweak =  _mm_set_epi32(0,0,0,i);

			//Deduce the key to encrypt
			block key = _mm_xor_si128(_mm_xor_si128(twoA, fourB), tweak);
			//encryptedKey = key;

			int rowIndex;//The row in the current garbled table for the specific gate.
			
			if(isRowReduction==true){
				rowIndex = 2*a + b - 1;//the row index in the garbled table of row reduction is should be minus one of a regular circuit since we only have 3 rows.
				
			}
			else{
				rowIndex = 2*a + b;
			}

			//ancrypt 2A+4B+T.
			AES_encryptC(&key, &encryptedKey, aesFixedKey);

			//For row reduction and the first row compute the calculated row.
			if(isRowReduction && rowIndex==-1){
				//the output of the gate is computaed rather than calclulated using the garbled table
				computedWires[garbledGates[i].output] = _mm_xor_si128(encryptedKey, key);
			}
			else{//get the computedWire key using Xor'ss with the related row in the garbled table.
				
				//calc the output
				computedWires[garbledGates[i].output] = _mm_xor_si128(_mm_xor_si128(encryptedKey, key), garbledTables[jumpInGarblesTable* nonXorIndex + rowIndex]);
			}
			//increment the nonXor gates number only for the non-xor (not XOR or XOR_NOT) gates. For circuits
			//That do not use FreeXor optimization it will be incremented for every gate
			nonXorIndex++;
		}
		
	}
	

	if (isNonXorOutputsRequired){//check if the user requires that the output keys will not have a fixed delta xor between pair of keys of a wire.

		//call the function that returns the Output where xoring with the other wire key will not have fixed delta for all the outputs
		computeOutputWiresToNoFixedDelta(nonXorIndex, Output);
	}

	else{
		//copy the output wire keys which are the result the user is interested in.
		for (int i = 0; i < numberOfOutputs; i++) {
			Output[i] = computedWires[outputIndices[i]];

		}
	}


}


void GarbledBooleanCircuit::computeOutputWiresToNoFixedDelta(int nonXorIndex, block * Output){
	
	for (int i = 0; i < numberOfOutputs; i++){
		
		block twoA = _mm_slli_epi64(computedWires[outputIndices[i]], 1);//make one shift
		block tweak = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);//contine the tweak from the point we have stoped to make sure we do
																				//not use the same tweak twice
		//create the key "2A XOR Tweak"
		block key = _mm_xor_si128(twoA, tweak);
		block encryptedKey;
		//encrypt the key to retrieve from the garbled table the computed key
		AES_encryptC(&key, &encryptedKey, aesFixedKey);


		int jumpInGarblesTable;

		if (isTwoRows){
			jumpInGarblesTable = 2;
		}
		else if (isRowReduction){
			jumpInGarblesTable = 3;//every gate only consumes 3 blocks
		}
		else{
			jumpInGarblesTable = 4;//every gate consumes 4 blocks
		}

		//get the computedWires using the garbled table that contain "enc(key) XOR key Xor output"
		if (getSignalBitOf(computedWires[outputIndices[i]]) == 0){//in case the 0-wire has 0 signal bit
			computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2]));
		}
		else{//in case the 0-wire has 1 signal bit
			computedWires[lastWireIndex + 1 + i] = _mm_xor_si128(encryptedKey, _mm_xor_si128(key, garbledTables[jumpInGarblesTable* nonXorIndex + i * 2 + 1]));
		}

		//finally 
		Output[i] = computedWires[lastWireIndex + 1 + i];

	}

}

void GarbledBooleanCircuit::verifyOutputWiresToNoFixedDelta(block *bothOutputsKeys){

	//The result of chunk encrypting indexArray.
	block* encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
	//The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
	block* indexArray = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//Since we are using ecb mode, the plaintext must be different for every encryption
	for (int i = 0; i < numberOfOutputs; i++){
		indexArray[i] = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);
	}

	//Encrypt the entire array to have random variablesto use for the output wires
	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		numberOfOutputs,
		aesSeedKey);




	//update the output to be without fixed delta between all the wires of each key.
	for (int i = 0; i < numberOfOutputs; i++) {

		//build the garbled wires of the identity gates, note that the wire with signal bit 0 stays the same
		if (getSignalBitOf(bothOutputsKeys[2 * i]) == 0){
			*((unsigned char *)(&encryptedChunkKeys[i])) |= 1;
			bothOutputsKeys[2 * i + 1] = encryptedChunkKeys[i];
		}
		else{
			*((unsigned char *)(&encryptedChunkKeys[i])) &= 0;
			bothOutputsKeys[2 * i] = encryptedChunkKeys[i];
		}

	}

}



void GarbledBooleanCircuit::garbleOutputWiresToNoFixedDelta(block *deltaFreeXor, int nonXorIndex, block *emptyBothOutputKeys){

	//The result of chunk encrypting indexArray.
	block* encryptedChunkKeys = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//An array that holds the number numberOfGates - numOfXorGates to the number of numberOfGates - numOfXorGates + numberOfOutputs.
	//The purpuse of this array is to encrypt all the number of outputs in one chucnk. This gains piplining
	block* indexArray = (block *)_aligned_malloc(sizeof(block)* numberOfOutputs, 16);

	//Since we are using ecb mode, the plaintext must be different for every encryption
	for (int i = 0; i < numberOfOutputs; i++){
		indexArray[i] = _mm_set_epi32(0, 0, 0, numberOfGates - numOfXorGates + i);
	}

	//Encrypt the entire array to have random variablesto use for the output wires
	AES_ecb_encrypt_chunk_in_out(indexArray,
		encryptedChunkKeys,
		numberOfOutputs,
		aesSeedKey);

	int jumpInGarblesTable;
	if (isTwoRows){
		jumpInGarblesTable = 2;//every gate only consumes 2 blocks
	}
	else if (isRowReduction){
		jumpInGarblesTable = 3;//every gate only consumes 3 blocks
	}
	else{
		jumpInGarblesTable = 4;//every gate consumes 4 blocks
	}

	//make a nother layer of identity gates to make the output wire have different delta xor between them.
	for (int i = 0; i < numberOfOutputs; i++) {

		//build the garbled wires of the identity gates
		if (getSignalBitOf(garbledWires[outputIndices[i]]) == 0){
			garbledWires[lastWireIndex + 1 + 2 * i] = garbledWires[outputIndices[i]];
			*((unsigned char *)(&encryptedChunkKeys[i])) |= 1;
			garbledWires[lastWireIndex + 1 + 2 * i + 1] = encryptedChunkKeys[i];
		}
		else{
			*((unsigned char *)(&encryptedChunkKeys[i])) &= 0;
			garbledWires[lastWireIndex + 1 + 2 * i] = encryptedChunkKeys[i];
			garbledWires[lastWireIndex + 1 + 2 * i + 1] = garbledWires[outputIndices[i]];
		}

		block TwoA[2];
		block keys[2];
		block encryptedKeys[2];


		//Shift int inputs of the identity gates (the output of the freeXor circuit) by one
		TwoA[0] = _mm_slli_epi64(garbledWires[outputIndices[i]], 1);
		TwoA[1] = _mm_slli_epi64(_mm_xor_si128(garbledWires[outputIndices[i]], *deltaFreeXor), 1);

		//Calc the keys "2A XOR tweak"
		keys[0] = _mm_xor_si128(TwoA[0], indexArray[i]);
		keys[1] = _mm_xor_si128(TwoA[1], indexArray[i]);

		//encrypt the keys to use in the garbled tables
		AES_encryptC(&keys[0], &encryptedKeys[0], aesFixedKey);
		AES_encryptC(&keys[1], &encryptedKeys[1], aesFixedKey);

		//create the garbled table with 2 entries for each identity gate
		if (getSignalBitOf(garbledWires[outputIndices[i]]) == 0){
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i] = _mm_xor_si128(encryptedKeys[0], _mm_xor_si128(keys[0], garbledWires[lastWireIndex + 1 + 2 * i]));
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i + 1] = _mm_xor_si128(encryptedKeys[1], _mm_xor_si128(keys[1], garbledWires[lastWireIndex + 1 + 2 * i + 1]));
		}
		else{
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i + 1] = _mm_xor_si128(encryptedKeys[0], _mm_xor_si128(keys[0], garbledWires[lastWireIndex + 1 + 2 * i]));
			garbledTables[jumpInGarblesTable * nonXorIndex + 2 * i] = _mm_xor_si128(encryptedKeys[1], _mm_xor_si128(keys[1], garbledWires[lastWireIndex + 1 + 2 * i + 1]));

		}

		//copy the new output keys to get back to the caller of the function.
		emptyBothOutputKeys[2 * i] = garbledWires[lastWireIndex + 1 + 2 * i];
		emptyBothOutputKeys[2 * i + 1] = garbledWires[lastWireIndex + 1 + 2 * i + 1];

	}



}

bool GarbledBooleanCircuit::verify(block *bothInputKeys){

	block *emptyBothWireOutputKeys = (block *) _aligned_malloc(sizeof(block)  * numberOfOutputs*2, 16); 

	//Call the internal internalVerify function that verifies all the gates but does not check the translation table.
	bool isVerified = internalVerify(bothInputKeys,emptyBothWireOutputKeys);

	//Check that the results of the internal verify comply with the translation table.
	if(isVerified==true){
		isVerified = verifyTranslationTable(emptyBothWireOutputKeys);

	}


	//Free the localy allocated memory
	_aligned_free(emptyBothWireOutputKeys);
	return isVerified;

}


bool  GarbledBooleanCircuit::equalBlocks(block a, block b)
{ 
	//A function that checks if two blocks are equal by casting to double size long array and check each half of a block
	long *ap = (long*) &a;
	long *bp = (long*) &b;
	if ((ap[0] == bp[0]) && (ap[1] == bp[1]))
		return 1;
	else{
		return 0;
	}
}


bool GarbledBooleanCircuit::verifyTranslationTable(block * bothWireOutputKeys)
{
	bool isVerified = true;
	//go over the output key results and make sure that they comply with the translation table
	for (int i=0; i<numberOfOutputs;i++) {
		block zeroBlock = bothWireOutputKeys[2*i];
		block oneBlock = bothWireOutputKeys[2*i+1];

		unsigned char translatedZeroValue = translationTable[i] ^ getSignalBitOf(zeroBlock);
		unsigned char translatedOneValue = translationTable[i] ^ getSignalBitOf(oneBlock);

		//Verify that the translatedZeroValue is actually 0 and that translatedOneValue is indeed 1
		if (translatedZeroValue != 0 || translatedOneValue != 1) {
			isVerified = false;
			break;
		}
	}	return isVerified;
}

void GarbledBooleanCircuit::readCircuitFromFile(const char* fileName)
{

	int inFan, outFan, input0, input1, output, type, typeBin, numOfinputsForParty;
	int currentPartyNumber;
	ifstream myfile;

	
	myfile.open(fileName);
	

	int **partiesInputs;

	int numOfNonXorGate = 0;


	if (myfile.is_open())
	{
		
		myfile >> numberOfGates;//get the gates
		myfile >> numberOfParties;

		numOfInputsForEachParty = new int[numberOfParties];
		partiesInputs = new int*[numberOfParties];

		for(int j=0 ; j<numberOfParties; j++){
			myfile >> currentPartyNumber;

			myfile >> numOfinputsForParty;
			numOfInputsForEachParty[currentPartyNumber-1] = numOfinputsForParty;

			partiesInputs[currentPartyNumber-1] = new int[numOfInputsForEachParty[currentPartyNumber-1]];

			for(int i = 0; i<numOfInputsForEachParty[currentPartyNumber-1]; i++){
				myfile >>partiesInputs[currentPartyNumber-1][i];
			}
		}


		//get the number of outputs
		myfile >> numberOfOutputs;

		//allocate memory for the output number of wires and get each wire number into the array of outputs indices
		outputIndices = new int[numberOfOutputs];

		for(int i=0;i < numberOfOutputs;i++){
			myfile >> outputIndices[i];
		}


		//calculate the total number of inputs
		for(int i=0; i<numberOfParties;i++){
			numberOfInputs+=numOfInputsForEachParty[i];
		}

		//allocate memory for the gates, We add one gate for the all-one gate whose output is always 1 and thus have a wire who is always 1 without the 
		//involvement of the user. This will be useful to turn a NOT gate into a XORGate
		garbledGates = new GarbledGate[numberOfGates];


		//write the inputs to the inputs array of the garbled circuit
		inputIndices = new int[numberOfInputs];

		int index = 0;
		for(int i=0;i <numberOfParties; i++){
			for(int j=0; j< numOfInputsForEachParty[i]; j++){

				inputIndices[index] = partiesInputs[i][j];
				index++;
			}
		}

		//create a one-gate for the NOT gates
		
		//garbledGates[0].truthTable = ONE_GATE;
		//garbledGates[0].input0 = inputIndices[0];
		//garbledGates[0].input1 = inputIndices[0];
		//garbledGates[0].output = -1;//the outputWire is defined to be -1. 

		//Increment the garbled gates pointer so the one gate will be in -1 location and the other gates will start with 0.
		//We will do the same when allocating wires.
		//garbledGates = garbledGates + 1;


		//create a gate whose output is always 1. This gate number will be -1 and we will move the poiter one place 
		//go over the file and create gate by gate
		for(int i=0; i<numberOfGates;i++)
		{

			//get  each row that represents a gate
			myfile >> inFan;
			myfile >> outFan;
			myfile >> input0;

			if (inFan != 1)//a 2 input 1 output gate - regualr gate, else we have a not gate
			{
				myfile >> input1;					
			}

			
			myfile >> output;
			myfile >> typeBin;


			if(lastWireIndex < output){
				lastWireIndex = output;
			}

			if (inFan == 1)//NOT gate
			{
				input1 = -1;
				type = XOR_GATE;

				garbledGates[i].truthTable = type;
			}
			else{
				type = binaryTodecimal(typeBin);

				garbledGates[i].truthTable = type;
			}


			//Just garbled require that the first input number would be less than the second one. If this is the case, we need to switch between bit2 and bit3 in order
			//to switch the labels and still get the required truth table


			//transform the binary string to a decimal number between 0-15. That is if the truth table string was "0110", typeBin gets the value 110 in decimal since it 
			//is an int. This function transforms it to the decimal number 6 (XOR_GATE).
			

			//we build the truth table in a way that we only need to get a specific row instead of doing a lot of shifts
			garbledGates[i].truthTableBits[0] = getRowTruthTableResultShifts(0, type);
			garbledGates[i].truthTableBits[1] = getRowTruthTableResultShifts(1, type);
			garbledGates[i].truthTableBits[2] = getRowTruthTableResultShifts(2, type);
			garbledGates[i].truthTableBits[3] = getRowTruthTableResultShifts(3, type);

			garbledGates[i].input0 = input0;
			garbledGates[i].input1 = input1;
			garbledGates[i].output = output;

			if ((type == XOR_GATE || type == XOR_NOT_GATE) && isFreeXor == true){
				
					numOfXorGates++;
				
			}

		}

		for (int i = 0; i < numberOfParties; ++i)
			delete[] partiesInputs[i];
		delete[] partiesInputs;

	}
	myfile.close();
}
