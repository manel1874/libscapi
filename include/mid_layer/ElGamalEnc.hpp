#pragma once
#include "AsymmetricEnc.hpp"
#include "../infra/Common.hpp"
#include "../primitives/Dlog.hpp"
#include "../primitives/DlogOpenSSL.hpp"

class ElGamalPublicKeySendableData : public KeySendableData {
private:
	shared_ptr<GroupElementSendableData> c;

public:
	ElGamalPublicKeySendableData(shared_ptr<GroupElementSendableData> c) {
		this->c = c;
	}

	shared_ptr<GroupElementSendableData> getC() { return c; }

	string toString() override { return c->toString(); }
	void initFromString(const string & raw) override { c->initFromString(raw); }
};

/**
* This class represents a Public Key suitable for the El Gamal Encryption Scheme. Although the constructor is public, it should only be instantiated by the
* Encryption Scheme itself via the generateKey function.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class ElGamalPublicKey : public PublicKey {

private:
	shared_ptr<GroupElement> h;

public:
	ElGamalPublicKey(shared_ptr<GroupElement> h) {
		this->h = h;
	}

	shared_ptr<GroupElement> getH() { return h; }

	shared_ptr<KeySendableData> generateSendableData() {
		return make_shared<ElGamalPublicKeySendableData>(h->generateSendableData());
	}
	string getAlgorithm() override { return "ElGamal"; }
	vector<byte> getEncoded() override { throw UnsupportedOperationException("cannot decode a group element to byte array"); }
};

/**
* This class represents a Private Key suitable for the El Gamal Encryption Scheme. Although the constructor is public, it should only be instantiated by the
* Encryption Scheme itself via the generateKey function.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class ElGamalPrivateKey : public PrivateKey, KeySendableData {

private:
	biginteger x;

public:
	ElGamalPrivateKey(biginteger x) { this->x = x; }

	biginteger getX() {	return x; }

	string toString() override { return string(x); }
	void initFromString(const string & row) override {	x = biginteger(row); }
	string getAlgorithm() override { return "ElGamal"; }
	vector<byte> getEncoded() override { throw NotImplementedException(""); }
};

//Nested class that holds the sendable data of the outer class
class ElGamalOnGrElSendableData : public AsymmetricCiphertextSendableData {

private:
	shared_ptr<GroupElementSendableData> cipher1;
	shared_ptr<GroupElementSendableData> cipher2;

public:
	ElGamalOnGrElSendableData(shared_ptr<GroupElementSendableData> cipher1,
		shared_ptr<GroupElementSendableData> cipher2) {
		this->cipher1 = cipher1;
		this->cipher2 = cipher2;
	}
	shared_ptr<GroupElementSendableData> getCipher1() { return cipher1; }
	shared_ptr<GroupElementSendableData> getCipher2() { return cipher2; }
	string toString() override { return cipher1->toString() + ":" + cipher2->toString(); }
	void initFromString(const string & row) override;
};

/**
* This class is a container that encapsulates the cipher data resulting from applying the ElGamalOnGroupElement encryption.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class ElGamalOnGroupElementCiphertext : public AsymmetricCiphertext {
private:
	//First part of the ciphertext.
	shared_ptr<GroupElement> cipher1;
	//Second part of the ciphertext.
	shared_ptr<GroupElement> cipher2;

public:
	/**
	* Create an instance of this container class.
	* This constructor is used by the Encryption Scheme as a result of a call to function encrypt.
	* @param c1 the first part of the cihertext
	* @param c2 the second part of the ciphertext
	*/
	ElGamalOnGroupElementCiphertext(shared_ptr<GroupElement> c1, shared_ptr<GroupElement> c2) {
		this->cipher1 = c1;
		this->cipher2 = c2;
	}

	/**
	*
	* @return the first part of the ciphertext
	*/
	shared_ptr<GroupElement> getC1() { return cipher1; }

	/**
	*
	* @return the second part of the ciphertext
	*/
	shared_ptr<GroupElement> getC2() { return cipher2; }

	shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() override {
		return make_shared<ElGamalOnGrElSendableData>(cipher1->generateSendableData(), cipher2->generateSendableData());
	}

	bool operator==(const AsymmetricCiphertext &other) const override {
		auto temp = dynamic_cast<const ElGamalOnGroupElementCiphertext*>(&other);
		if (*cipher1 != *(temp->cipher1)) 
			return false;
		
		return *cipher2 == *(temp->cipher2);
	}
};

/**
* This class performs the El Gamal encryption scheme that perform the encryption on a GroupElement. <P>
* In some cases there are protocols that do multiple calculations and might want to keep working on a close group.
* For those cases we provide encryption on a group element. <P>
*
* By definition, this encryption scheme is CPA-secure and Indistinguishable.
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
*
*/
class ElGamalOnGroupElementEnc : public AsymMultiplicativeHomomorphicEnc {
private:

	shared_ptr<DlogGroup> dlog;						//The underlying DlogGroup
	shared_ptr<ElGamalPrivateKey> privateKey;		//ElGamal private key (contains x)
	shared_ptr<ElGamalPublicKey> publicKey;			//ElGamal public key (contains h)
	mt19937 random;									//Source of randomness
	bool keySet;
	biginteger qMinusOne;							//We keep this value to save unnecessary calculations.

	void setMembers(shared_ptr<DlogGroup> dlogGroup);

public:
	/**
	* Default constructor. Uses the default implementations of DlogGroup, CryptographicHash and SecureRandom.
	*/
	ElGamalOnGroupElementEnc();

	/**
	* Constructor that gets a DlogGroup and sets it to the underlying group.
	* It lets SCAPI choose and source of randomness.
	* @param dlogGroup underlying DlogGroup to use, it has to have DDH security level
	* @throws SecurityLevelException if the Dlog Group is not DDH secure
	*/
	ElGamalOnGroupElementEnc(shared_ptr<DlogGroup> dlogGroup) {
		setMembers(dlogGroup);
	}

	/**
	* Initializes this ElGamal encryption scheme with (public, private) key pair.
	* After this initialization the user can encrypt and decrypt messages.
	* @param publicKey should be ElGamalPublicKey.
	* @param privateKey should be ElGamalPrivateKey.
	* @throws InvalidKeyException if the given keys are not instances of ElGamal keys.
	*/
	void setKey(shared_ptr<PublicKey> publicKey, shared_ptr<PrivateKey> privateKey) override;

	/**
	* Initializes this ElGamal encryption scheme with public key.
	* Setting only the public key the user can encrypt messages but can not decrypt messages.
	* @param publicKey should be ElGamalPublicKey
	* @throws InvalidKeyException if the given key is not instances of ElGamalPuclicKey.
	*/
	void setKey(shared_ptr<PublicKey> publicKey) override {	setKey(publicKey, NULL); }

	bool isKeySet() override { return keySet; }

	/**
	* Returns the PublicKey of this ElGamal encryption scheme.
	* This function should not be use to check if the key has been set.
	* To check if the key has been set use isKeySet function.
	* @return the ElGamalPublicKey
	* @throws IllegalStateException if no public key was set.
	*/
	shared_ptr<PublicKey> getPublicKey() override {
		if (!isKeySet()) {
			throw new IllegalStateException("no PublicKey was set");
		}

		return publicKey;
	}

	/**
	* @return the name of this AsymmetricEnc - ElGamal and the underlying dlog group type
	*/
	string getAlgorithmName() override {	return "ElGamal/" + dlog->getGroupType(); }

	/**
	* Generates a KeyPair containing a set of ElGamalPublicKEy and ElGamalPrivateKey using the source of randomness and the dlog specified upon construction.
	* @return KeyPair contains keys for this ElGamal object.
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey() override;

	/**
	* This function is not supported for this encryption scheme, since there is no need for parameters to generate an ElGamal key pair.
	* @throws UnsupportedOperationException
	*/
	pair<shared_ptr<PublicKey>, shared_ptr<PrivateKey>> generateKey(AlgorithmParameterSpec* keyParams) override{
		//No need for parameters to generate an El Gamal key pair. 
		throw new UnsupportedOperationException("To Generate ElGamal keys use the generateKey() function");
	}

	shared_ptr<PublicKey> reconstructPublicKey(KeySendableData* data) override;

	shared_ptr<PrivateKey> reconstructPrivateKey(KeySendableData* data) override;

	/**
	* Encrypts the given message using ElGamal encryption scheme.
	*
	* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	* @return Ciphertext containing the encrypted message.
	* @throws IllegalStateException if no public key was set.
	* @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(shared_ptr<Plaintext> plaintext) override;

	/**
	* Encrypts the given plaintext using this asymmetric encryption scheme and using the given random value.<p>
	* There are cases when the random value is used after the encryption, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when more than one value is being encrypt.
	* Instead, we decided to have an additional encrypt value that gets the random value from the user.
	*
	* @param plaintext contains message to encrypt. The given plaintext must match this ElGamal type.
	* @param r The random value to use in the encryption.
	* @return Ciphertext containing the encrypted message.
	* @throws IllegalStateException if no public key was set.
	* @throws IllegalArgumentException if the given Plaintext does not match this ElGamal type.
	*/
	shared_ptr<AsymmetricCiphertext> encrypt(shared_ptr<Plaintext> plaintext, biginteger r) override;

	/**
	* El-Gamal encryption scheme has a limit of the byte array length to generate a plaintext from.
	* @return true.
	*/
	bool hasMaxByteArrayLengthForPlaintext() override { return true;	}

	/**
	* Returns the maximum size of the byte array that can be passed to generatePlaintext function.
	* This is the maximum size of a byte array that can be converted to a Plaintext object suitable to this encryption scheme.
	*/
	int getMaxLengthOfByteArrayForPlaintext() override {	return dlog->getMaxLengthOfByteArrayForEncoding(); }

	/**
	* Generates a Plaintext suitable to ElGamal encryption scheme from the given message.
	* @param text byte array to convert to a Plaintext object.
	* @throws IllegalArgumentException if the given message's length is greater than the maximum.
	*/
	shared_ptr<Plaintext> generatePlaintext(vector<byte> text) override;

	/**
	* Decrypts the given ciphertext using ElGamal encryption scheme.
	*
	* @param cipher MUST be of type ElGamalOnGroupElementCiphertext contains the cipher to decrypt.
	* @return Plaintext of type GroupElementPlaintext which containing the decrypted message.
	* @throws KeyException if no private key was set.
	* @throws IllegalArgumentException if the given cipher is not instance of ElGamalOnGroupElementCiphertext.
	*/
	shared_ptr<Plaintext> decrypt(AsymmetricCiphertext* cipher) override;

	/**
	* Generates a byte array from the given plaintext.
	* This function should be used when the user does not know the specific type of the Asymmetric encryption he has,
	* and therefore he is working on byte array.
	* @param plaintext to generates byte array from. MUST be an instance of GroupElementPlaintext.
	* @return the byte array generated from the given plaintext.
	* @throws IllegalArgumentException if the given plaintext is not an instance of GroupElementPlaintext.
	*/
	vector<byte> generateBytesFromPlaintext(Plaintext* plaintext) override;

	/**
	* Calculates the ciphertext resulting of multiplying two given ciphertexts.
	* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.
	* @throws IllegalStateException if no public key was set.
	* @throws IllegalArgumentException in the following cases:
	* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	*/
	shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2) override;

	/**
	* Calculates the ciphertext resulting of multiplying two given ciphertexts.<P>
	* Both ciphertexts have to have been generated with the same public key and DlogGroup as the underlying objects of this ElGamal object.<p>
	*
	* There are cases when the random value is used after the function, for example, in sigma protocol.
	* In these cases the random value should be known to the user. We decided not to have function that return it to the user
	* since this can cause problems when the multiply function is called more than one time.
	* Instead, we decided to have an additional multiply function that gets the random value from the user.
	*
	* @throws IllegalStateException if no public key was set.
	* @throws IllegalArgumentException in the following cases:
	* 		1. If one or more of the given ciphertexts is not instance of ElGamalOnGroupElementCiphertext.
	* 		2. If one or more of the GroupElements in the given ciphertexts is not a member of the underlying DlogGroup of this ElGamal encryption scheme.
	*/
	shared_ptr<AsymmetricCiphertext> multiply(AsymmetricCiphertext* cipher1, AsymmetricCiphertext* cipher2, biginteger r) override;

	
	/**
	* @see edu.biu.scapi.midLayer.asymmetricCrypto.encryption.AsymmetricEnc#reconstructCiphertext(edu.biu.scapi.midLayer.ciphertext.AsymmetricCiphertextSendableData)
	*/
	shared_ptr<AsymmetricCiphertext> reconstructCiphertext(AsymmetricCiphertextSendableData* data) override;
};
