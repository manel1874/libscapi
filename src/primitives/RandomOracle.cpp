#include "../../include/primitives/RandomOracle.hpp"

void HashBasedRO::compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) {
	if (outLen > hash->getHashedMsgSize())
		throw invalid_argument("The given output length is greater then the output length of the hash function");
	// call the hash function with the input.
	hash->update(input, inOffset, inLen);
	// compute the hash function.
	hash->hashFinal(output, 0);
	output.resize(outLen);
}

void HKDFBasedRO::compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) {
	// call the HKDF function with input, output length and iv = "RandomOracle".
	string iv_str = "RandomOracle";
	vector<byte> v_source(iv_str.begin(), iv_str.end());
	v_source.push_back('\0');
	SecretKey key = hkdf->deriveKey(input, inOffset, inLen, outLen, &v_source);
	output = key.getEncoded();
}

HashBasedRO::~HashBasedRO()
{
	delete this->hash;
}

HKDFBasedRO::~HKDFBasedRO()
{
	//delete this->hkdf;
}