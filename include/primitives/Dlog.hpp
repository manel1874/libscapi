#pragma once

#include "../infra/Common.hpp"
#include "SecurityLevel.hpp"
#include "../infra/MathAlgorithms.hpp"

class InvalidDlogGroupException : public logic_error
{
public:
	InvalidDlogGroupException(const string & msg) : logic_error(msg) {};
};


/**
* This is the main interface of the Group element hierarchy.<p>
* We can refer to a group element as a general term OR we can relate to the fact that an element of an elliptic curve
* is a point and an element of a Zp group is a number between 0 and p-1.
*
*/
class GroupElement : public NetworkSerialized
{

protected:
	int serialized_size;

public:
	/**
	* checks if this element is the identity of the group.
	* @return <code>true</code> if this element is the identity of the group;<p>
	* 		   <code>false</code> otherwise.
	*/
	virtual bool isIdentity() = 0;

	virtual bool operator==(const GroupElement &other) const=0;
	virtual bool operator!=(const GroupElement &other) const=0;
	virtual ~GroupElement() {};

	virtual int getSerializedSize() override { return serialized_size; };
};

/*
* The GroupParams family holds the necessary parameters for each possible concrete Dlog group. <p>
* Each DlogGroup has different parameters that constitute this group. GroupParams classes hold those parameters.
*/
class GroupParams
{
protected:
	biginteger q; // the group order

public:
	/*
	* Returns the group order, which is the number of elements in the group
	* @return the order of the group
	*/
	biginteger getQ() { return q; }
	
	// making this class and abstract one
	virtual ~GroupParams() = 0;
};

inline GroupParams::~GroupParams() { };

/**
* This is the general interface for the discrete logarithm group. 
* Every class in the DlogGroup family implements this interface.
* The discrete logarithm problem is as follows: given a generator g of a finite group G and 
* a random element h in G, find the (unique) integer x such that g^x = h.
* In cryptography, we are interested in groups for which the discrete logarithm problem (Dlog for short) is assumed to be hard.<p>
* The two most common classes are the group Zp* for a large p, and some Elliptic curve groups.<p>
*
* Another issue pertaining elliptic curves is the need to find a suitable mapping that will convert an arbitrary message (that is some binary string) to an element of the group and vice-versa.<p>
* Only a subset of the messages can be effectively mapped to a group element in such a way that there is a one-to-one injection that converts the string to a group element and vice-versa.<p>
* On the other hand, any group element can be mapped to some string.<p>
* In this case, the operation is not invertible. This functionality is implemented by the functions:<p>
*  - {@code encodeByteArrayToGroupElement(byte[] binaryString) : GroupElement}<p>
*  - {@code decodeGroupElementToByteArray(GroupElement element) : byte[]}<p>
*  - {@code mapAnyGroupElementToByteArray(GroupElement element) : byte[]}<p>
*
*  The first two work as a pair and decodeGroupElementToByteArray is the inverse of encodeByteArrayToGroupElement, whereas the last one works alone and does not have an inverse.
*/
class DlogGroup : public enable_shared_from_this<DlogGroup>  
{
protected:
	std::shared_ptr<GroupParams> groupParams;  // group parameters
	std::shared_ptr<GroupElement> generator;	// generator of the group
	mt19937 random_element_gen;

	int k; // k is the maximum length of a string to be converted to a Group Element of this group.
		   // If a string exceeds the k length it cannot be converted.

		   /*
		   * Computes the simultaneousMultiplyExponentiate using a naive algorithm
		   */
	std::shared_ptr<GroupElement> computeNaive(vector<std::shared_ptr<GroupElement>> groupElements,
		vector<biginteger> exponentiations);

	/*
	* Compute the simultaneousMultiplyExponentiate by LL algorithm.
	* The code is taken from the pseudo code of LL algorithm in http://dasan.sejong.ac.kr/~chlim/pub/multi_exp.ps.
	*/
	std::shared_ptr<GroupElement> computeLL(vector<std::shared_ptr<GroupElement>> groupElements,
		vector<biginteger> exponentiations);

private:
	/**
	* The class GroupElementExponentiations is a nested class of DlogGroupAbs.<p>
	* It performs the actual work of pre-computation of the exponentiations for one base.
	* It is composed of two main elements. The group element for which the optimized computations
	* are built for, called the base and a vector of group elements that are the result of
	* exponentiations of order 1,2,4,8,
	*/
	class GroupElementsExponentiations {
	private:
		vector<std::shared_ptr<GroupElement>> exponentiations; //vector of group elements that are the result of exponentiations
		std::shared_ptr<GroupElement> base;  //group element for which the optimized computations are built for
		std::shared_ptr<DlogGroup> parent;
		/**
		* Calculates the necessary additional exponentiations and fills the exponentiations vector with them.
		* @param size - the required exponent
		* @throws IllegalArgumentException
		*/
		void prepareExponentiations(biginteger size);

	public:
		/**
		* The constructor creates a map structure in memory.
		* Then calculates the exponentiations of order 1,2,4,8 for the given base and save them in the map.
		* @param base
		* @throws IllegalArgumentException
		*/
		GroupElementsExponentiations(std::shared_ptr<DlogGroup> parent_,
			std::shared_ptr<GroupElement> base_);

		/**
		* Checks if the exponentiations had already been calculated for the required size.
		* If so, returns them, else it calls the private function prepareExponentiations with the given size.
		* @param size - the required exponent
		* @return groupElement - the exponentiate result
		*/
		shared_ptr<GroupElement> getExponentiation(biginteger size);
	};
	// using pointer as key mean different element ==> different keys even if they are 'equal' in other sense
	std::unordered_map<std::shared_ptr<GroupElement>,
		std::shared_ptr<GroupElementsExponentiations >> exponentiationsMap; //map for multExponentiationsWithSameBase calculations

	/*
	* Computes the loop the repeats in the algorithm.
	* for k=0 to h-1
	* 		e=0
	* 		for i=kw to kw+w-1
	*			if the bitIndex bit in ci is set:
	*			calculate e += 2^(i-kw)
	*		result = result *preComp[k][e]
	*
	*/
	std::shared_ptr<GroupElement> computeLoop(vector<biginteger> exponentiations, int w, int h,
		vector<vector<std::shared_ptr<GroupElement>>> preComp, std::shared_ptr<GroupElement> result,
		int bitIndex);

	/*
	* Creates the preComputation table.
	*/
	vector<vector<std::shared_ptr<GroupElement>>> createLLPreCompTable(
		vector<std::shared_ptr<GroupElement>> groupElements, int w, int h);

	/*
	* returns the w value according to the given t
	*/
	int getLLW(int t);

public:
	/**
	* Each concrete class implementing this interface returns a string with a meaningful name for this type of Dlog group.
	* For example: "elliptic curve over F2m" or "Zp*"
	* @return the name of the group type
	*/
	virtual string getGroupType() = 0;

	/**
	* The generator g of the group is an element of the group such that, when written multiplicatively, every element of the group is a power of g.
	* @return the generator of this Dlog group
	*/
	shared_ptr<GroupElement> getGenerator() { return generator; }
	
	/**
	* GroupParams is a structure that holds the actual data that makes this group a specific Dlog group.<p>
	* For example, for a Dlog group over Zp* what defines the group is p.
	*
	* @return the GroupParams of that Dlog group
	*/
	shared_ptr<GroupParams> getGroupParams() { return groupParams; }

	/**
	* If this group has been initialized then it returns the group's order. Otherwise throws exception.
	* @return the order of this Dlog group
	*/
	biginteger getOrder() { return groupParams->getQ(); };
	
	/**
	*
	* @return the identity of this Dlog group
	*/
	virtual std::shared_ptr<GroupElement> getIdentity() = 0;

	/**
	* Checks if the given element is a member of this Dlog group
	* @param element possible group element for which to check that it is a member of this group
	* @return <code>true</code> if the given element is a member of this group;<p>
	* 		   <code>false</code> otherwise.
	* @throws IllegalArgumentException
	*/
	virtual bool isMember(shared_ptr<GroupElement> element) = 0;

	/**
	* Checks if the order is a prime number.<p>
	* Primality checking can be an expensive operation and it should be performed only when absolutely necessary.
	* @return true if the order is a prime number. false, otherwise.
	*/
	virtual bool isPrimeOrder() { return isPrime(getOrder()); }
	
	/**
	* Checks if the order is greater than 2^numBits
	* @param numBits
	* @return true if the order is greater than 2^numBits, false - otherwise.
	*/
	bool isOrderGreaterThan(int numBits) { return (getOrder() > boost::multiprecision::pow(biginteger(2), numBits)); }
	
	/**
	* Checks if the element set as the generator is indeed the generator of this group.
	* @return <code>true</code> if the generator is valid;<p>
	*         <code>false</code> otherwise.
	*/
	virtual bool isGenerator() = 0;

	/**
	* Checks parameters of this group to see if they conform to the type this group is supposed to be.
	* @return <code>true</code> if valid;<p>
	*  	   <code>false</code> otherwise.
	*/
	virtual bool validateGroup() = 0;

	/**
	* Calculates the inverse of the given GroupElement.
	* @param groupElement to invert
	* @return the inverse element of the given GroupElement
	* @throws IllegalArgumentException
	**/
	virtual std::shared_ptr<GroupElement> getInverse(std::shared_ptr<GroupElement> groupElement) = 0;

	/**
	* Raises the base GroupElement to the exponent. The result is another GroupElement.
	* @param exponent
	* @param base
	* @return the result of the exponentiation
	* @throws IllegalArgumentException
	*/
	virtual std::shared_ptr<GroupElement> exponentiate(std::shared_ptr<GroupElement> base, biginteger exponent) = 0;

	/**
	* Multiplies two GroupElements
	* @param groupElement1
	* @param groupElement2
	* @return the multiplication result
	* @throws IllegalArgumentException
	*/
	virtual std::shared_ptr<GroupElement> multiplyGroupElements(std::shared_ptr<GroupElement> groupElement1, 
		std::shared_ptr<GroupElement> groupElement2) = 0;

	/**
	* Creates a random member of this Dlog group
	* @return the random element
	*/
	virtual std::shared_ptr<GroupElement> createRandomElement();

	/**
	* Creates a random generator of this Dlog group
	* @return the random generator
	*/
	std::shared_ptr<GroupElement> createRandomGenerator();

	/**
	* This function allows the generation of a group element by a protocol that holds a Dlog Group but does not know if it is a Zp Dlog Group or an Elliptic Curve Dlog Group.
	* It receives the possible values of a group element and whether to check membership of the group element to the group or not.
	* It may be not necessary to check membership if the source of values is a trusted source (it can be the group itself after some calculation). On the other hand,
	* to work with a generated group element that is not really an element in the group is wrong. It is up to the caller of the function to decide if to check membership or not.
	* If bCheckMembership is false always generate the element. Else, generate it only if the values are correct.
	* @param bCheckMembership
	* @param values
	* @return the generated GroupElement
	* @throws IllegalArgumentException
	*/
	virtual std::shared_ptr<GroupElement> generateElement(bool bCheckMembership, vector<biginteger> values) = 0;

	/**
	* Computes the product of several exponentiations with distinct bases
	* and distinct exponents.
	* Instead of computing each part separately, an optimization is used to
	* compute it simultaneously.
	* @param groupElements
	* @param exponentiations
	* @return the exponentiation result
	*/
	virtual std::shared_ptr<GroupElement> simultaneousMultipleExponentiations(
		vector<std::shared_ptr<GroupElement>> groupElements, vector<biginteger> exponentiations) = 0;

	/**
	* Computes the product of several exponentiations of the same base
	* and distinct exponents.
	* An optimization is used to compute it more quickly by keeping in memory
	* the result of h1, h2, h4,h8,... and using it in the calculation.<p>
	* Note that if we want a one-time exponentiation of h it is preferable to use the basic exponentiation function
	* since there is no point to keep anything in memory if we have no intention to use it.
	* @param base
	* @param exponent
	* @return the exponentiation result
	*/
	virtual std::shared_ptr<GroupElement> exponentiateWithPreComputedValues(
		std::shared_ptr<GroupElement> base, biginteger exponent);

	/**
	* This function cleans up any resources used by exponentiateWithPreComputedValues for the requested base.
	* It is recommended to call it whenever an application does not need to continue calculating exponentiations for this specific base.
	*
	* @param base
	*/
	void endExponentiateWithPreComputedValues(std::shared_ptr<GroupElement> base) {
		exponentiationsMap.erase(base);
	}
	
	/**
	* This function takes any string of length up to k bytes and encodes it to a Group Element.
	* k can be obtained by calling getMaxLengthOfByteArrayForEncoding() and it is calculated upon construction of this group; it depends on the length in bits of p.<p>
	* The encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not every group element can be decoded to a binary string in the group of binary strings of length up to 2^k.<p>
	* Thus, the right way to use this functionality is first to encode a byte array and then to decode it, and not the opposite.
	*
	* @param binaryString the byte array to encode
	* @return the encoded group Element <B> or null </B>if element could not be encoded
	*/
	virtual  std::shared_ptr<GroupElement> encodeByteArrayToGroupElement(
		const vector<unsigned char> & binaryString) = 0;

	/**
	* This function decodes a group element to a byte array. This function is guaranteed to work properly ONLY if the group element was obtained as a result of
	* encoding a binary string of length in bytes up to k.<p>
	* This is because the encoding-decoding functionality is not a bijection, that is, it is a 1-1 function but is not onto.
	* Therefore, any string of length in bytes up to k can be encoded to a group element but not any group element can be decoded
	* to a binary sting in the group of binary strings of length up to 2^k.
	*
	* @param groupElement the element to decode
	* @return the decoded byte array
	*/
	virtual const vector<unsigned char> decodeGroupElementToByteArray(
		std::shared_ptr<GroupElement> groupElement) = 0;


	/**
	* This function returns the value k which is the maximum length of a string to be encoded to a Group Element of this group.
	* Any string of length k has a numeric value that is less than (p-1)/2 - 1.
	* k is the maximum length a binary string is allowed to be in order to encode the said binary string to a group element and vice-versa.
	* If a string exceeds the k length it cannot be encoded.
	* @return k the maximum length of a string to be encoded to a Group Element of this group. k can be zero if there is no maximum.
	*/
	virtual int getMaxLengthOfByteArrayForEncoding() {
		//Return member variable k, which was calculated upon construction of this Dlog group, once the group got the p value. 
		return k;
	};
	
	/**
	* This function maps a group element of this dlog group to a byte array.<p>
	* This function does not have an inverse function, that is, it is not possible to re-construct the original group element from the resulting byte array.
	* @return a byte array representation of the given group element
	*/
	virtual const vector<byte> mapAnyGroupElementToByteArray(
		std::shared_ptr<GroupElement> groupElement) = 0;
};

/**
* Marker interface for Dlog groups that has a prime order sub-group.
*/
class primeOrderSubGroup : public virtual DlogGroup {};

/**********DlogZP hierechy***********************/

/**
* Marker interface. Every class that implements it is signed as Zp*
*/
class DlogZp : public DlogGroup {};

/**
* This class holds the parameters of a Dlog group over Zp*.
*/
class ZpGroupParams : public GroupParams{
private:
	biginteger p; //modulus
	biginteger xG; //generator value

public:
	/**
	* constructor that sets the order, generator and modulus
	* @param q - order of the group
	* @param xG - generator of the group
	* @param p - modulus of the group
	*/
	ZpGroupParams(biginteger q_, biginteger xG_, biginteger p_) {
		q = q_;
		xG = xG_;
		p = p_;
	}

	/**
	* Returns the prime modulus of the group
	* @return p
	*/
	biginteger getP() { return p; }

	/**
	* Returns the generator of the group
	* @return xG - the generator value
	*/
	biginteger getXg() { return xG; }
	
	/* For Serlialization */
	string toString() { return "ZpGroupParams [p=" + (string) p + ", g=" + (string) xG + ", q=" + (string) q + "]"; }
};

/**
* Marker interface. Every class that implements it is signed as Zp* group were p is a safe prime.
*/
class DlogZpSafePrime : public DlogZp {};

/**
* This is a marker interface. Every class that implements it is signed as Zp* element.
*/
class ZpElement : public GroupElement {
	/**
	* This function returns the actual "integer" value of this element; which is an element of a given Dlog over Zp*.
	* @return integer value of this Zp element.
	*/
public:
	virtual biginteger getElementValue()=0;
};

/**
* This is a marker interface. Every class that implements it is marked as an element of a sub-group of prime order of Zp* where p is a safe prime.
*/
class ZpSafePrimeElement : public ZpElement {
protected:
	biginteger element = 0;
public:
	/**
	* This constructor accepts x value and DlogGroup (represented by p).
	* If x is valid, sets it; else, throws exception
	*/
	ZpSafePrimeElement(biginteger x, biginteger p, bool bCheckMembership);
	/**
	* Constructor that gets DlogGroup and chooses random element with order q.
	* The algorithm is:
	* input: modulus p
	* choose a random element between 1 to p-1
	* calculate element^2 mod p
	*/
	ZpSafePrimeElement(biginteger p, mt19937 prg);
	/*
	* Constructor that simply create element using the given value
	*/
	ZpSafePrimeElement(biginteger elementValue) { 
		element = elementValue; 
		serialized_size = bytesCount(element);
	};
	biginteger getElementValue() override { return element; };
	bool isIdentity() override { return element == 1; }
	bool operator==(const GroupElement &other) const override;
	bool operator!=(const GroupElement &other) const override;
	virtual string toString() = 0; 

	std::shared_ptr<byte> toByteArray() override {
		serialized_size = bytesCount(element);
		std::shared_ptr<byte> result(new byte[serialized_size], std::default_delete<byte[]>());
		encodeBigInteger(element, result.get(), serialized_size);
		return result;
	};
	void initFromByteArray(byte* arr, int size) override {
		serialized_size = size;
		element = decodeBigInteger(arr, size);
	};
};

