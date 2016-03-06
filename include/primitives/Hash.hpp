#ifndef SCAPI_HASH_H
#define SCAPI_HASH_H

#include "../infra/Common.hpp"
#include "SecurityLevel.hpp"

/**
* A hash function is target collision resistant if it is infeasible for an adversary to succeed in the following game:
* the adversary chooses a message x;
* next a random key K is chosen for the hash function and given to the adversary;
* finally the adversary outputs some y (not equal to x) such that H_K(x)=H_K(y).<p>
* Observe that this notion is of relevance for KEYED hash functions (note that the key is public, but randomly chosen).
*/
class TargetCollisionResistant : HashSecLevel {};

/**
* A hash function H is collision resistant if it is infeasible to find two distinct values x and y such that H(x)=H(y).
*/
class CollisionResistant : TargetCollisionResistant {};

/**
* General interface for CryptographicHash. Every concrete class should implement this interface. <p>
* A cryptographic hash function is a deterministic procedure that takes an arbitrary block of data and returns a fixed-size bit string,
* the (cryptographic) hash value.
*/
class CryptographicHash {
public:
	virtual ~CryptographicHash() {};
	/**
	* @return The algorithm name. For example - SHA1
	*/
	virtual string getAlgorithmName()=0;

	/**
	* @return the size of the hashed massage in bytes
	*/
	virtual int getHashedMsgSize()=0;

	/**
	* Adds the byte array to the existing message to hash.
	* @param in input byte array
	* @param inOffset the offset within the byte array
	* @param inLen the length. The number of bytes to take after the offset
	* */
	virtual void update(const vector<byte> &in, int inOffset, int inLen)=0;

	/**
	* Completes the hash computation and puts the result in the out array.
	* @param out the output in byte array
	* @param outOffset the offset which to put the result bytes from
	*/
	virtual void hashFinal(vector<byte> &out, int outOffset)=0;

	/**
	* Factory method. Create concrete instance of the give algorithm name in the default implementation. 
	*/
	static CryptographicHash* get_new_cryptographic_hash(string hash_name="SHA1");
};

/*****************************************************************
* SHA Marker interfaces. Every class that implements them is signed as SHA:
******************************************************************/
class SHA1   : public virtual CryptographicHash, public virtual CollisionResistant {};
class SHA224 : public virtual CryptographicHash, public virtual CollisionResistant {};
class SHA256 : public virtual CryptographicHash, public virtual CollisionResistant {};
class SHA384 : public virtual CryptographicHash, public virtual CollisionResistant {};
class SHA512 : public virtual CryptographicHash, public virtual CollisionResistant {};

#endif