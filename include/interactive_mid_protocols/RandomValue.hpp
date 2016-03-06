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