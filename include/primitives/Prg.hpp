/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#ifndef SCAPI_PRG_H
#define SCAPI_PRG_H

#include "../infra/Common.hpp"
#include "../CryptoInfra/Key.hpp"
#include "Prf.hpp"
#include <openssl/rc4.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <emmintrin.h>


typedef unsigned char byte;
typedef __m128i block;

#define DEFAULT_CACHE_SIZE 64
#define BLOCK_SIZE 16

/**
* Parameters for PrgFromPrf key generation.
*/
class PrgFromPrfParameterSpec : public AlgorithmParameterSpec {
private:
	vector<byte> entropySource;	// random bit sequence.=
	int prfKeySize;		// Prf key size in bits.

public:	
	/**
	* Constructor that gets a random bit sequence which is the entropy source, and prf key size in 
	* bits and sets them.
	*/
	PrgFromPrfParameterSpec(vector<byte> entropySource, int prfKeySize) {
		this->entropySource = entropySource;
		this->prfKeySize = prfKeySize;
	};
	vector<byte> getEntropySource() { return entropySource; };
	int getPrfKeySize() { return prfKeySize; };
};

/**
* General interface of pseudorandom generator. Every concrete class in this family should implement this interface. <p>
*
* A pseudorandom generator (PRG) is a deterministic algorithm that takes a short uniformly distributed string,
* known as the seed, and outputs a longer string that cannot be efficiently distinguished from a uniformly
* distributed string of that length.
*/
class PseudorandomGenerator {
public:
	/**
	* Sets the secret key for this prg.
	* The key can be changed at any time.
	*/
	virtual void setKey(SecretKey secretKey)=0;
	/**
	* An object trying to use an instance of prg needs to check if it has already been initialized with a key.
	* @return true if the object was initialized by calling the function setKey.
	*/
	virtual bool isKeySet()=0;
	/**
	* @return the algorithm name. For example - RC4
	*/
	virtual string getAlgorithmName()=0;
	/**
	* Generates a secret key to initialize this prg object.
	* @param keyParams algorithmParameterSpec contains the required parameters for the key generation
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(AlgorithmParameterSpec keyParams)=0;
	/**
	* Generates a secret key to initialize this prg object.
	* @param keySize is the required secret key size in bits
	* @return the generated secret key
	*/
	virtual SecretKey generateKey(int keySize)=0;
	/**
	* Streams the prg bytes.
	* @param outBytes - output bytes. The result of streaming the bytes.
	* @param outOffset - output offset
	* @param outlen - the required output length
	*/
	virtual void getPRGBytes(vector<byte> & outBytes, int outOffset, int outlen)=0;
};

/**
* Marker interface. Each RC4 concrete class should implement this interface.
*/
class RC4 : public PseudorandomGenerator {};

/**
* This is a simple way of generating a pseudorandom stream from a pseudorandom function.
* The seed for the pseudorandom generator is the key to the pseudorandom function.
* Then, the algorithm initializes a counter to 1 and applies the pseudorandom function to the counter, 
* increments it, and repeats.
*/
class ScPrgFromPrf : public PseudorandomGenerator {
private:
	PseudorandomFunction * prf;	// Underlying PRF.
	vector<byte> ctr;			// Counter used for key generation.
	bool _isKeySet=false;
	/**
	* Increases the ctr byte array by 1 bit.
	*/
	void increaseCtr();

public:
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prf underlying PseudorandomFunction.
	*/
	ScPrgFromPrf(PseudorandomFunction * prf) {this->prf = prf; };
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prfName PseudorandomFunction algorithm name.
	*/
	ScPrgFromPrf(string prfName) : ScPrgFromPrf(PseudorandomFunction::get_new_prf(prfName)) {};

	void setKey(SecretKey secretKey) override;
	bool isKeySet() override { return _isKeySet; };
	string getAlgorithmName() override { return "PRG_from_" + prf->getAlgorithmName(); };
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override { return prf->generateKey(keyParams); };
	SecretKey generateKey(int keySize) override { return prf->generateKey(keySize); };
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;
};


/**
* This is a simple way of generating a pseudorandom stream from a pseudorandom function.
* The seed for the pseudorandom generator is the key to the pseudorandom function.
* Then, the algorithm initializes a counter to 1 and applies the pseudorandom function to the counter,
* increments it, and repeats.
*/
class prgFromOpenSSLAES : public PseudorandomGenerator {
private:
			// Counter used for key generation.
	block iv = _mm_setzero_si128();

	int cachedSize;
	int idxForBytes = 0;
	int startingIndex = 0;
	unique_ptr<EVP_CIPHER_CTX> aes;
	bool _isKeySet = false;
	block* cipherChunk;
	block* indexPlaintext;
	bool isStrict;

public:
	/**
	* Constructor that lets the user choose the underlying PRF algorithm.
	* @param prf underlying PseudorandomFunction.
	*/
	prgFromOpenSSLAES(int cachedSize = 1280, bool isStrict = false);

	//move assignment
	prgFromOpenSSLAES& operator=(prgFromOpenSSLAES&& other);
	//copy assignment
	prgFromOpenSSLAES& operator=(prgFromOpenSSLAES& other) = delete;
	
	//move constructor
	prgFromOpenSSLAES(prgFromOpenSSLAES&& old);
	//copy constructor
	prgFromOpenSSLAES(prgFromOpenSSLAES& other) = delete;

	~prgFromOpenSSLAES();
	

	void setKey(SecretKey secretKey) override;
	bool isKeySet() override { return _isKeySet; };
	string getAlgorithmName() override { return "prgFromOpenSSLAES"; };
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override {
		throw NotImplementedException("To generate a key for this prg object use the generateKey(int keySize) function");
	}
	SecretKey generateKey(int keySize) override;
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;
	uint32_t getRandom32();
	uint64_t getRandom64();
	block getRandom128();

	void prepare();
};



/**
* This class wraps the OpenSSL implementation of RC4.
* RC4 is a well known stream cipher, that is essentially a pseudorandom generator.<p>
* In our implementation, we throw out the first 1024 bits since the first few bytes have been shown
* to have some bias.
**/
class OpenSSLRC4 : public RC4 {
private:
	RC4_KEY *rc4; //pointer to the openssl RC4 object.
	mt19937 random;
	bool _isKeySet=false;

public:
	OpenSSLRC4() {
		this->random = get_seeded_random();
		rc4 = new RC4_KEY();
	}
	void setKey(SecretKey secretKey) override;	
	bool isKeySet() override { return _isKeySet; };
	string getAlgorithmName() override { return "RC4"; };
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override{
		throw NotImplementedException("To generate a key for this prg object use the generateKey(int keySize) function");
	}
	SecretKey generateKey(int keySize) override;
	void getPRGBytes(vector<byte> & outBytes, int outOffset, int outLen) override;
	~OpenSSLRC4();
};


#endif