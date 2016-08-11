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


#ifndef SCAPI_OPENSSL_PRF_H
#define SCAPI_OPENSSL_PRF_H

#include "Prf.hpp"
#include "HashOpenSSL.hpp"
#include "Prg.hpp"
#include "../CryptoInfra/Key.hpp"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>


class OpenSSLPRP : public PrpFixed {
	
protected:
	shared_ptr<PrgFromOpenSSLAES> prg;
	EVP_CIPHER_CTX* computeP;	//Native object used to compute the prp.
	EVP_CIPHER_CTX* invertP;		//Native object used to invert the prp.
	bool _isKeySet;

public:
	bool isKeySet() override { return _isKeySet; }
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override {
		throw NotImplementedException("To generate a key for this prf object use the generateKey(int keySize) function");
	};
	SecretKey generateKey(int keySize) override;
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) override;
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) override;
	void computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) override;
	/**
	* Computes the permutation on the given array.
	* The given array length does not have to be the size of the block but a MUST be aligned to the block size.
	* The optimized compute block divide the given input into blocks and compute each one of them separately.
	* The output array will contain a concatenation of all the results of computing the blocks.
	*
	* @param inBytes input bytes to compute.
	* @param outBytes output bytes. The resulted bytes of compute.
	* @throws IllegalArgumentException if the given input is not aligned to block size.
	* @throws IllegalArgumentException if the given input and output are not in the same size.
	*/
	void optimizedCompute(const vector<byte> & inBytes, vector<byte> &outBytes);
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) override;
	/**
	* Inverts the permutation on the given array.
	* The given array length does not have to be the size of the block but a MUST be aligned to the block size.
	* The optimized invert block divides the given input into blocks and inverts each one of them separately.
	* The output array will contain a concatenation of all the results of inverting the blocks.
	*
	* @param inBytes input bytes to invert.
	* @param outBytes output bytes. The inverted bytes.
	* @throws IllegalArgumentException if the given input is not aligned to block size.
	* @throws IllegalArgumentException if the given input and output are not in the same size.
	*/
	void optimizedInvert(const vector<byte> & inBytes, vector<byte> &outBytes);
	void invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) override;
	virtual ~OpenSSLPRP();
};
/**
* Concrete class of PRF family for AES. This class wraps the implementation of OpenSSL library.
*/
class OpenSSLAES : public OpenSSLPRP, public AES {
private: 
	void init(shared_ptr<PrgFromOpenSSLAES> setRandom);
public:
	/**
	* Default constructor that creates the AES objects. Uses default implementation of SecureRandom.
	*/
	OpenSSLAES();

	OpenSSLAES(shared_ptr<PrgFromOpenSSLAES> setRandom) { init(setRandom); }

	/**
	* Initializes this AES objects with the given secret key.
	* @param secretKey secret key.
	* @throws InvalidKeyException if the key is not 128/192/256 bits long.
	*/
	void setKey(SecretKey secretKey) override;
	string getAlgorithmName() override { return "AES"; };
	int getBlockSize() override { return 16; };
	virtual ~OpenSSLAES() {};
};

class OpenSSLHMAC : public Hmac {
private:
	HMAC_CTX * hmac; //Pointer to the native hmac.
	bool _isKeySet; //until setKey is called set to false.
	mt19937 random; //source of randomness used in key generation
	void construct(string hashName);

public: 
	/**
	* Default constructor that uses SHA1.
	*/
	OpenSSLHMAC() { construct("SHA-1"); };
	/**
	* This constructor receives a hashName and builds the underlying hmac according to it. It can be called from the factory.
	* @param hashName - the hash function to translate into OpenSSL's hash.
	* @throws FactoriesException if there is no hash function with given name.
	*/
	OpenSSLHMAC(string hashName) { construct(hashName); };

	/**
	* This constructor gets a random and a SCAPI CryptographicHash to be the underlying hash and retrieves the name of the hash in
	* order to create the related OpenSSL's hash.
	* @param hash - the underlying hash to use.
	* @param random the random object to use.
	* @throws FactoriesException if there is no hash function with given name.
	*/
	OpenSSLHMAC(CryptographicHash *hash) { construct(hash->getAlgorithmName()); };
	/**
	* Initializes this hmac with a secret key.
	* @param secretKey the secret key
	*/
	void setKey(SecretKey secretKey) override;
	void setMacKey(SecretKey secretKey) override { setKey(secretKey); };
	bool isKeySet() override { return _isKeySet; };
	string getAlgorithmName() override;
	int getBlockSize() override { return EVP_MD_size(hmac->md); };
	void computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) override;
	void computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) override;
	void computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) override;
	SecretKey generateKey(AlgorithmParameterSpec keyParams) override {
		throw NotImplementedException("To generate a key for this HMAC object use the generateKey(int keySize) function");
	};
	SecretKey generateKey(int keySize) override;
	int getMacSize() override { return getBlockSize(); };
	virtual vector<byte> mac(const vector<byte> &msg, int offset, int msgLen) override;
	virtual bool verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) override;
	virtual void update(vector<byte> & msg, int offset, int msgLen) override;
	virtual void doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) override;
	~OpenSSLHMAC();
};

/**
* Concrete class of PRF family for Triple DES. This class wraps the implementation of OpenSSL library.
*/
class OpenSSLTripleDES : public OpenSSLPRP, public TripleDES {
public:
	/**
	* Default constructor that creates the TripleDES objects. Uses default implementation of SecureRandom.
	*/
	OpenSSLTripleDES();
	void setKey(SecretKey secretKey) override;
	string getAlgorithmName() override{ return "TripleDES"; };
	int getBlockSize() override { return 8; }; // TripleDES works on 64 bit block.
};

#endif