#ifndef SCAPI_KEY_H
#define SCAPI_KEY_H

#include "../infra/Common.hpp"
class Key {
public:
	/*
	* Returns the name of the algorithm associated with this key.
	*/
	virtual string getAlgorithm()=0;
	virtual vector<byte> getEncoded()=0;
};

class SecretKey : Key {
private:
	vector<byte> key;
	string algorithm;

public:
	SecretKey() {};
	SecretKey(byte * keyBytes, int keyLen, string algorithm) {
		copy_byte_array_to_byte_vector(keyBytes, keyLen, this->key, 0);
		this->algorithm = algorithm;
	}
	SecretKey(const vector<byte> & key, string algorithm) {
		this->key = key;
		this->algorithm = algorithm;
	};
	string getAlgorithm() override { return algorithm; };
	vector<byte> getEncoded() override { return key; };
};

class PublicKey : public Key {};
class PrivateKey : public Key {};
class KeySendableData : public NetworkSerialized {};
class KeySpec {};

class KeyPair {
private:
	PublicKey * publicKey;
	PrivateKey * privateKey;
public:
	KeyPair(PublicKey * pubk, PrivateKey * pvk) {
		publicKey = pubk;
		privateKey = pvk;
	};
	PublicKey * GetPublic() { return publicKey; };
	PrivateKey * GetPrivate() { return privateKey; };
};

class RSAKey {
private:
	biginteger modulus;
public:
	RSAKey(biginteger mod) { modulus = mod; };
	biginteger getModulus() { return modulus; };
};

class RSAPublicKey : public RSAKey, public PublicKey {
private:
	biginteger publicExponent;
public:
	RSAPublicKey(biginteger mod, biginteger pubExp) : RSAKey(mod) { publicExponent = pubExp; };
	biginteger getPublicExponent() { return publicExponent; };
	string getAlgorithm() override { return "RSA"; };
	vector<byte> getEncoded() override { throw NotImplementedException(""); };
};

class RSAPrivateKey : public RSAKey, public PrivateKey {
private:
	biginteger privateExponent;
public:
	RSAPrivateKey(biginteger mod, biginteger privExp) : RSAKey(mod) { privateExponent = privExp; };
	biginteger getPrivateExponent() { return privateExponent; };
	string getAlgorithm() override { return "RSA"; };
	vector<byte> getEncoded() override { throw NotImplementedException(""); };
};

class RSAPrivateCrtKey : public RSAPrivateKey {
public:
	virtual biginteger getPublicExponent() = 0;
	virtual biginteger getPrimeP() = 0;
	virtual biginteger getPrimeQ() = 0;
	virtual biginteger getPrimeExponentP() = 0;
	virtual biginteger getPrimeExponentQ() = 0;
	virtual biginteger getCrtCoefficient() = 0;
};

class AlgorithmParameterSpec {};

class RSAKeyGenParameterSpec : public AlgorithmParameterSpec {};
#endif