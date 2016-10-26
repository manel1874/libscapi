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


#pragma once
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "TrapdoorPermutations.hpp"
#include "DlogOpenSSL.hpp"
/**
* Concrete class of trapdoor permutation of RSA algorithm.
* This class wraps the OpenSSL implementation of RSA permutation.
*/
class OpenSSLRSAPermutation : public virtual TrapdoorPermutationAbs , public virtual RSAPermutation {
private:
	RSA* rsa; // Pointer to the SSL RSA object.
	shared_ptr<PrgFromOpenSSLAES> random;
	RSA* initRSAPublicPrivateCrt(biginteger pubExp, biginteger privExp, biginteger p, 
		biginteger q, biginteger dp, biginteger dq, biginteger crt);
	RSA* initRSAPublicPrivate(biginteger pubExponent, biginteger privExponent);
	RSA * initRSAPublic(biginteger pubExponent);
	biginteger computeRSA(biginteger elementP);

public:
	OpenSSLRSAPermutation(const shared_ptr<PrgFromOpenSSLAES> & random = get_seeded_prg()) { this->random = random; };
	void setKey(PublicKey* publicKey, PrivateKey* privateKey=NULL) override; 
	string getAlgorithmName() override { return "OpenSSLRSA"; };
	KeyPair generateKey(int keySize) override;
	TPElement* compute(TPElement * tpEl) override;
	TPElement* invert(TPElement * tpEl) override;
	TPElValidity isElement(TPElement* tpEl) override;
	TPElement* generateRandomTPElement() override;
	TPElement* generateTPElement(biginteger x) override { return new RSAElement(x); };
	TPElement* generateUncheckedTPElement(biginteger x) override { return new RSAElement(modulus, x, false); };
	biginteger getModulus() override {
		if (!isKeySet())
			throw IllegalStateException("keys aren't set");
		return modulus;
	};
	~OpenSSLRSAPermutation();
};

