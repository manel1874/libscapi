#pragma once

#include <openssl/dh.h>
#include <openssl/ec.h>
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
	OpenSSLZpSafePrimeElement(const biginteger & x, const biginteger & p, bool bCheckMembership) : 
		ZpSafePrimeElement(x, p, bCheckMembership) {};
	OpenSSLZpSafePrimeElement(const biginteger & p, mt19937 prg) : ZpSafePrimeElement(p, prg) {};
	OpenSSLZpSafePrimeElement(const biginteger & elementValue) : ZpSafePrimeElement(elementValue) {};
	virtual string toString() {
		return "OpenSSLZpSafePrimeElement  [element value=" + string(element) + "]";
	};
	~OpenSSLZpSafePrimeElement() {};
};

/**
* This class implements a Dlog group over Zp* utilizing OpenSSL's implementation.<p>
*/
class OpenSSLDlogZpSafePrime : public DlogZpSafePrime, public DDH {
private:
	shared_ptr<OpenSSLDlogZpAdapter> dlog; // Pointer to the native group object.
	shared_ptr<OpenSSLDlogZpAdapter> createOpenSSLDlogZpAdapter(const biginteger & p, const biginteger & q, const biginteger & g);
	shared_ptr<OpenSSLDlogZpAdapter> createRandomOpenSSLDlogZpAdapter(int numBits);
	int calcK(const biginteger & p);

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
	bool isMember(GroupElement* element) override;
	bool isGenerator() override;
	bool validateGroup() override;
	shared_ptr<GroupElement> getInverse(GroupElement* groupElement) override;
	shared_ptr<GroupElement> exponentiate(GroupElement* base, const biginteger & exponent) override;
	shared_ptr<GroupElement> exponentiateWithPreComputedValues(shared_ptr<GroupElement> groupElement, 
		const biginteger & exponent) override { return exponentiate(groupElement.get(), exponent); };
	shared_ptr<GroupElement> multiplyGroupElements(GroupElement* groupElement1, 
		GroupElement* groupElement2) override;
	shared_ptr<GroupElement> simultaneousMultipleExponentiations(vector<shared_ptr<GroupElement>> groupElements,
		vector<biginteger> exponentiations) override;
	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> values) override;
	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;
	const vector<byte> decodeGroupElementToByteArray(GroupElement* groupElement) override;
	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;
	virtual const vector<byte>  mapAnyGroupElementToByteArray(GroupElement* groupElement) override;
};

class OpenSSLDlogEC : public DlogEllipticCurve{
	
protected:
	shared_ptr<EC_GROUP> curve;
	shared_ptr<BN_CTX> ctx;
	virtual shared_ptr<ECElement> createPoint(shared_ptr<EC_POINT>) = 0;
	shared_ptr<EC_GROUP> getCurve() { return curve; }
	shared_ptr<BN_CTX> getCTX() { return ctx; }

public:
	OpenSSLDlogEC(string fileName, string curveName, mt19937 random) : DlogEllipticCurve(fileName, curveName, random) { }

	OpenSSLDlogEC(string curveName, mt19937 random) : DlogEllipticCurve(curveName, random) { }

	bool validateGroup() override;

	shared_ptr<GroupElement> getInverse(GroupElement* groupElement) override;

	shared_ptr<GroupElement> exponentiate(GroupElement* base, const biginteger & exponent) override;

	shared_ptr<GroupElement> multiplyGroupElements(GroupElement* groupElement1,
		GroupElement* groupElement2) override;

	shared_ptr<GroupElement> exponentiateWithPreComputedValues(
		shared_ptr<GroupElement> base, const biginteger & exponent) override;

	shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		vector<shared_ptr<GroupElement>> groupElements, vector<biginteger> exponentiations) override;

	const vector<byte> mapAnyGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<ECElement> getInfinity() override;

};


class OpenSSLECFpPoint;

class OpenSSLDlogECFp : public OpenSSLDlogEC {
private:
	int calcK(biginteger p);
	void createCurve(const biginteger & p, const biginteger & a, const biginteger & b);
	void initCurve(const biginteger & q);
	bool checkSubGroupMembership(OpenSSLECFpPoint* point);
	

protected:
	shared_ptr<ECElement> createPoint(shared_ptr<EC_POINT>) override;
	void init(string fileName, string curveName, mt19937 random) override;

public:
	OpenSSLDlogECFp() : OpenSSLDlogECFp("P-192") { }

	OpenSSLDlogECFp(string fileName, string curveName, mt19937 random) : OpenSSLDlogEC(fileName, curveName, random) { init(fileName, curveName, random); }

	OpenSSLDlogECFp(string curveName, mt19937 random = get_seeded_random()) : OpenSSLDlogEC(curveName, random)  { init(NISTEC_PROPERTIES_FILE, curveName, random); }

	string getGroupType() override;

	bool isMember(GroupElement* element) override;

	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> values) override;

	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;

	const vector<unsigned char> decodeGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;
	
	friend class OpenSSLECFpPoint;
};

class OpenSSLECF2mPoint;

class OpenSSLDlogECF2m : public OpenSSLDlogEC {
private:
	void createGroupParams();
	void createCurve();
	bool checkSubGroupMembership(OpenSSLECF2mPoint*  point);
protected:
	void init(string fileName, string curveName, mt19937 random) override;
	shared_ptr<ECElement> createPoint(shared_ptr<EC_POINT>) override;

public:

	OpenSSLDlogECF2m() : OpenSSLDlogECF2m("K-163") {}

	OpenSSLDlogECF2m(string fileName, string curveName, mt19937 random): OpenSSLDlogEC(fileName, curveName, random) { init(fileName, curveName, random); }

	OpenSSLDlogECF2m(string curveName, mt19937 random = get_seeded_random()) : OpenSSLDlogEC(curveName, random) { init(NISTEC_PROPERTIES_FILE, curveName, random); }

	string getGroupType() override;

	bool isMember(GroupElement* element) override;

	shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> values) override;

	shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		vector<shared_ptr<GroupElement>> groupElements, vector<biginteger> exponentiations) override;

	shared_ptr<GroupElement> encodeByteArrayToGroupElement(const vector<unsigned char> & binaryString) override;

	const vector<unsigned char> decodeGroupElementToByteArray(GroupElement* groupElement) override;

	shared_ptr<GroupElement> reconstructElement(bool bCheckMembership, GroupElementSendableData* data) override;

	friend class OpenSSLECF2mPoint;
};

class OpenSSLPoint :public ECElement {
protected:
	shared_ptr<EC_POINT> point;
	shared_ptr<EC_POINT> getPoint() { return point; }
	biginteger x;
	biginteger y;
public:
	bool isInfinity() override;
	biginteger getX() override { return x; }
	biginteger getY() override { return y; }
	friend class OpenSSLDlogEC;
};

class OpenSSLECFpPoint : public OpenSSLPoint {
private:
	OpenSSLECFpPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECFp* curve, bool bCheckMembership);
	OpenSSLECFpPoint(shared_ptr<EC_POINT> point, OpenSSLDlogECFp* curve);

	bool checkCurveMembership(ECFpGroupParams* params, const biginteger & x, const biginteger & y);
public:
	friend class OpenSSLDlogECFp;
};

class OpenSSLECF2mPoint : public OpenSSLPoint, public enable_shared_from_this<OpenSSLECF2mPoint> {
private:
	OpenSSLECF2mPoint(const biginteger & x, const biginteger & y, OpenSSLDlogECF2m* curve, bool bCheckMembership);
	OpenSSLECF2mPoint(shared_ptr<EC_POINT> point, OpenSSLDlogECF2m* curve);
public:
	friend class OpenSSLDlogECF2m;
};
