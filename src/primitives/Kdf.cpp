#include "../../include/primitives/Kdf.hpp"

void HKDF::nextRounds(int outLen, const vector<byte> * iv, int hmacLength, vector<byte> & outBytes, vector<byte> & intermediateOutBytes) {
	int rounds = (int)ceil((float)outLen / (float)hmacLength); // the smallest number so that  hmacLength * rounds >= outLen
	int currentInBytesSize;	// the size of the CTXInfo and also the round;
	if (iv != NULL)
		currentInBytesSize = hmacLength + iv->size() + 1; // the size of the CTXInfo and also the round;
	else //no CTXInfo
		currentInBytesSize = hmacLength + 1; // the size without the CTXInfo and also the round;

	//the result of the current computation
	byte* currentInBytes = new byte[currentInBytesSize];

	int roundIndex;
	//for rounds 2 to t 
	if (iv != NULL)
		//in case we have an iv. puts it (ctxInfo after the K from the previous round at position hmacLength).
		copy_byte_vector_to_byte_array(*iv, currentInBytes, hmacLength);

	for (int i = 2; i <= rounds; i++) {
		// copies the output of the last results
		copy_byte_vector_to_byte_array(intermediateOutBytes, currentInBytes, 0);
		// copies the round integer to the data array
		currentInBytes[currentInBytesSize - 1] = (byte)i;
		
		//operates the hmac to get the round output 
		vector<byte> v_in;
		copy_byte_array_to_byte_vector(currentInBytes, currentInBytesSize, v_in, 0);
		this->hmac->computeBlock(v_in, 0, currentInBytesSize, intermediateOutBytes, 0);

		if (i == rounds)  //we fill the rest of the array with a portion of the last result.
			//copies the results to the output array
			outBytes.insert(outBytes.begin() + hmacLength*(i - 1), &intermediateOutBytes[0], &intermediateOutBytes[outLen - hmacLength*(i - 1)]);
		else 
			//copies the results to the output array
			outBytes.insert(outBytes.begin() + hmacLength*(i - 1), &intermediateOutBytes[0], &intermediateOutBytes[hmacLength]);
	}
}

void HKDF::firstRound(vector<byte>& outBytes, const vector<byte> * iv, vector<byte> & intermediateOutBytes, int outLength) {
	// round 1
	byte* firstRoundInput; //data for the creating K(1)
	int firstRoundSize;
	if (iv != NULL)
		firstRoundSize = iv->size() + 1;
	else
		firstRoundSize = 1;
	
	firstRoundInput = new  byte[firstRoundSize];

	// copies the CTXInfo - iv
	if (iv != NULL)
		copy_byte_vector_to_byte_array(*iv, firstRoundInput, 0);

	// copies the integer with zero to the data array
	firstRoundInput[firstRoundSize- 1] = (byte)1;

	// first computes the new key. The new key is the result of computing the hmac function.
	// calculate K(1) and put it in intermediateOutBytes.
	vector<byte> v_in;
	copy_byte_array_to_byte_vector(firstRoundInput, firstRoundSize, v_in, 0);
	hmac->computeBlock(v_in, 0, firstRoundSize, intermediateOutBytes, 0);

	// copies the results to the output array
	outBytes = intermediateOutBytes;
	//outBytes.insert(outBytes.begin(), &intermediateOutBytes[0], &intermediateOutBytes[outLength-1]);
}

SecretKey HKDF::deriveKey(const vector<byte> & entropySource, int inOff, int inLen, int outLen, const vector<byte>* iv) {
	//checks that the offset and length are correct
	if ((inOff > entropySource.size()) || (inOff + inLen > entropySource.size()))
		throw out_of_range("wrong offset for the given input buffer");

	//In order to be thread safe we have to synchronized this function.

	// Consider the following situation: thread #1 calls the deriveKey function. It starts to derive the key, 
	// calls the hmac setKey function and so on. In the meantime, thread #2 calls the deriveKey function as well.	
	// Without synchronization, thread #2 will set the hmac object with the fixed key (what is done in the beginning of 
	// the key derivation).
	// This will delete all thread #1 work until that time and the results of the deriveKey will be wrong.

	// By adding the synchronized block we let only one thread to be able execute the synchronized code at the same time. 
	// All other threads attempting to enter the synchronized block are blocked until the thread inside the 
	// synchronized block exits the block.

	unique_lock<mutex> lock(_mutex);
	
	// Sets the hmac object with a fixed key that was randomly generated once. This is done every time a new derived key is requested otherwise the result of deriving
	// a key from the same entropy source will be different in subsequent calls to this function (as long as the same instance of HKDF is used). 
	string str_key = boost::algorithm::unhex(string("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"));
	char const *c_key = str_key.c_str();
	hmac->setKey(SecretKey((byte*) c_key, strlen(c_key), ""));
	int hmacLength = hmac->getBlockSize(); //the size of the output of the hmac.
	vector<byte> outBytes;// (outLen); //the output key
	vector<byte> roundKey; //PRK from the pseudocode
	vector<byte> intermediateOutBytes;// (hmacLength); //round result K(i) in the pseudocode

	// first computes the new key. The new key is the result of computing the hmac function.
	//roundKey is now K(0)
	hmac->computeBlock(entropySource, 0, entropySource.size(), roundKey, 0);
	//init the hmac with the new key. From now on this is the key for all the rounds.
	hmac->setKey(SecretKey(roundKey, "HKDF"));
	
	// calculates the first round
	// K(1) = HMAC(PRK,(CTXinfo,1)) [key=PRK, data=(CTXinfo,1)]
	if (outLen < hmacLength)
		firstRound(outBytes, iv, intermediateOutBytes, outLen);
	else
		firstRound(outBytes, iv, intermediateOutBytes, hmacLength);

	// calculates the next rounds
	// FOR i = 2 TO t
	// K(i) = HMAC(PRK,(K(i-1),CTXinfo,i)) [key=PRK, data=(K(i-1),CTXinfo,i)]
	nextRounds(outLen, iv, hmacLength, outBytes, intermediateOutBytes);

	//creates the secret key from the generated bytes
	return SecretKey(outBytes, "HKDF");
	// Unlocking happens automatically since the lock
	// gets destroyed here.
}
