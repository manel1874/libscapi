#pragma once

#include <openssl/dh.h>
#include <openssl/rand.h>
#include "Dlog.hpp"

/**********************/
/**** Helpers *********/
/**********************/
biginteger opensslbignum_to_biginteger(BIGNUM* bint);
BIGNUM* biginteger_to_opensslbignum(biginteger bi);

class OpenSSLDlogZpAdapter {
private:
	shared_ptr<DH> dlog;
	shared_ptr<BN_CTX> ctx;
public:
	OpenSSLDlogZpAdapter(shared_ptr<DH> dlog, shared_ptr<BN_CTX> ctx);
	//~OpenSSLDlogZpAdapter();
	shared_ptr<DH> getDlog() { return dlog; };
	shared_ptr<BN_CTX> getCTX() { return ctx; };
	bool validateElement(BIGNUM* element);
};

/**
* This class is an adapter to ZpElement in OpenSSL library.<p>
* It holds a pointer to an OpenSSL's Zp element and implements all the functionality of a Zp element.
*/
class OpenSSLZpSafePrimeElement : public ZpSafePrimeElement {
public:
	OpenSSLZpSafePrimeElement(biginteger x, biginteger p, bool bCheckMembership) : 
		ZpSafePrimeElement(x, p, bCheckMembership) {};
	OpenSSLZpSafePrimeElement(biginteger p, mt19937 prg) : ZpSafePrimeElement(p, prg) {};
	OpenSSLZpSafePrimeElement(biginteger elementValue) : ZpSafePrimeElement(elementValue) {};
	virtual string toString() {
		return "OpenSSLZpSafePrimeElement  [element value=" + string(element) + "]";
	};
	~OpenSSLZpSafePrimeElement() {};
};

/**
* This class implements a Dlog group over Zp* utilizing OpenSSL's implementation.<p>
*/
class OpenSSLDlogZpSafePrime : public DlogGroupAbs, public DDH {
private:
	shared_ptr<OpenSSLDlogZpAdapter> dlog; // Pointer to the native group object.
	shared_ptr<OpenSSLDlogZpAdapter> createOpenSSLDlogZpAdapter(biginteger p, biginteger q, biginteger g);
	shared_ptr<OpenSSLDlogZpAdapter> createRandomOpenSSLDlogZpAdapter(int numBits);
	int calcK(biginteger p);

public:
	//virtual ~OpenSSLDlogZpSafePrime();
	/**
	* Initializes the OpenSSL implementation of Dlog over Zp* with the given groupParams.
	*/
	OpenSSLDlogZpSafePrime(std::shared_ptr<ZpGroupParams> groupParams,
		mt19937 prg =get_seeded_random());
	OpenSSLDlogZpSafePrime(string q, string g, string p) : OpenSSLDlogZpSafePrime(
		make_shared<ZpGroupParams>(biginteger(q), biginteger(g), biginteger(p))) {};
	/**
	* Default constructor. Initializes this object with 1024 bit size.
	*/
	OpenSSLDlogZpSafePrime(int numBits = 1024, mt19937 prg = mt19937(clock()));
	OpenSSLDlogZpSafePrime(string numBits) : OpenSSLDlogZpSafePrime(stoi(numBits)) {};
	OpenSSLDlogZpSafePrime(int numBits, string randNumGenAlg) { /* TODO: implement */ };

	string getGroupType() override { return "Zp*"; }
	shared_ptr<GroupElement> getIdentity() override;
	shared_ptr<GroupElement> createRandomElement() override;
	bool isMember(shared_ptr<GroupElement> element) override;
	bool isGenerator() override;
	bool validateGroup() override;
	shared_ptr<GroupElement> getInverse(shared_ptr<GroupElement> groupElement) override;
	shared_ptr<GroupElement> exponentiate(shared_ptr<GroupElement> base, biginteger exponent) override;
	shared_ptr<GroupElement> exponentiateWithPreComputedValues(shared_ptr<GroupElement> groupElement, 
		biginteger exponent) override { return exponentiate(groupElement, exponent); };
	shared_ptr<GroupElement> multiplyGroupElements(shared_ptr<GroupElement> groupElement1, 
		shared_ptr<GroupElement> groupElement2) override;
	shared_ptr<GroupElement> simultaneousMultipleExponentiations(vector<shared_ptr<GroupElement>> groupElements,
		vector<biginteger> exponentiations) override;
	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> values) override;
	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, shared_ptr<GroupElementSendableData> data) override;
	const vector<byte> decodeGroupElementToByteArray(shared_ptr<GroupElement> groupElement) override;
	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;
	virtual const vector<byte>  mapAnyGroupElementToByteArray(shared_ptr<GroupElement> groupElement) override;
};

