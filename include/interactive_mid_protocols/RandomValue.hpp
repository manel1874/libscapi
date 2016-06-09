#pragma once
#include "../infra/Common.hpp"

/**
* General interface for random values.
*/
class RandomValue {
public :
	virtual ~RandomValue() {};
};

/**
* Concrete class for BigInteger random value.
*/
class BigIntegerRandomValue : public RandomValue {
private:
	biginteger r;
public:
	BigIntegerRandomValue(biginteger r) { this->r = r; };
	biginteger getR() { return r; };
};

/**
* Concrete class for byte[] random value.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class ByteArrayRandomValue : public RandomValue {
private:
	vector<byte> r;
public:
	ByteArrayRandomValue(vector<byte> r) { this->r = r; }
	vector<byte> getR() { return r; };
};