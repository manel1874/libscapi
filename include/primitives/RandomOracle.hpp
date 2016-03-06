#pragma once
#include "HashOpenSSL.hpp"
#include "Kdf.hpp"

/**
* This interface is the general interface of Random Oracle. Every class in this family should implement this interface.
* A random oracle is an oracle (a theoretical black box) that responds to every unique query with a (truly) random
* response chosen uniformly from its output domain, except that for any specific query, it responds the same way
* every time it receives that query.
*/
class RandomOracle {
public:	
	/**
	* @return the name of this Random Oracle algorithm.
	*/
	virtual string getAlgorithmName()=0;

	/**
	* Computes the random oracle function on the given input.
	* @param input input to compute the random oracle function on.
	* @param inOffset offset within the input to take the bytes from.
	* @param inLen length of the input.
	* @param outLen required output length IN BYTES.
	* @return a string with the required length.
	*/
	virtual void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) = 0;
};

/**
* Concrete class of random oracle based on CryptographicHash.
*/
class HashBasedRO : public RandomOracle {
private:
	CryptographicHash * hash; //The underlying object used to compute the random oracle function.
public:
	HashBasedRO(CryptographicHash * hash = new OpenSSLSHA1()) { this->hash = hash; };
	HashBasedRO(string hashName) : HashBasedRO(CryptographicHash::get_new_cryptographic_hash(hashName)) {};
	void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) override;
	string getAlgorithmName() override { return "HashBasedRO"; };
	~HashBasedRO();
};

/**
* Concrete class of random oracle based on HKDF.
*/
class HKDFBasedRO : public RandomOracle {
private:
	HKDF* hkdf; //The underlying object used to compute the random oracle function.

public:	
	HKDFBasedRO(HKDF * hkdf) { this->hkdf = hkdf; };
	void compute(const vector<byte> & input, int inOffset, int inLen, vector<byte> & output, int outLen) override;
	string getAlgorithmName() override { return "HKDFBasedRO"; };
	~HKDFBasedRO();
};
