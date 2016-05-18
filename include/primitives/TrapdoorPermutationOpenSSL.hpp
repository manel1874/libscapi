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
	mt19937 random;
	RSA* initRSAPublicPrivateCrt(biginteger pubExp, biginteger privExp, biginteger p, 
		biginteger q, biginteger dp, biginteger dq, biginteger crt);
	RSA* initRSAPublicPrivate(biginteger pubExponent, biginteger privExponent);
	RSA * initRSAPublic(biginteger pubExponent);
	biginteger computeRSA(biginteger elementP);

public:
	OpenSSLRSAPermutation() { this->random = get_seeded_random(); };
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

