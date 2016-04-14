#pragma once
#include "../infra/Common.hpp"
#include "../primitives/Dlog.hpp"

/**
* This is a marker interface. It allows the generation of an AsymmetricCiphertext at
* an abstract level.
*/
class PlaintextSendableData : public NetworkSerialized {};


/**
* This is a marker interface for all plain-texts.
*/
class Plaintext {
public:
	/**
	* This function is used when a Plaintex needs to be sent via 
	* a Channel or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this Plaintext at a later time
	* and/or in a different environment.
	* It puts all the data in an instance of the relevant class that implements the
	* PlaintextSendableData interface.
	* @return the PlaintextSendableData object
	*/
	virtual shared_ptr<PlaintextSendableData> generateSendableData()=0;
	virtual bool operator==(const Plaintext &other) const = 0;
};

/**
* This class holds the plaintext as a BigInteger.
*/
class BigIntegerPlainText : public Plaintext, public PlaintextSendableData {
private:
	biginteger x;

public:
	biginteger getX() const { return x; };
	BigIntegerPlainText(biginteger x) { this->x = x; };
	BigIntegerPlainText(string s) { this->x = biginteger(s); };
	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const BigIntegerPlainText*>(&other);

		const biginteger x1 = temp->getX();
		return (x1==x);
	};

	shared_ptr<PlaintextSendableData> generateSendableData() override {
		// since BigIntegerPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		shared_ptr<PlaintextSendableData> res(this);
		return res;
	}

	string toString() override { return (string)x; };
	void initFromString(const string & raw) override { x = biginteger(raw); }
};

/**
* This class holds the plaintext as a ByteArray.
*/
class ByteArrayPlaintext : public Plaintext, public PlaintextSendableData {
private:
	vector<byte> text;
public:
	ByteArrayPlaintext(vector<byte> text) { this->text = text; };
	vector<byte> getText() const { return text; };
	int getTextSize() const { return text.size(); };

	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const ByteArrayPlaintext*>(&other);

		vector<byte> text2 = temp->getText();
		int len2 = temp->getTextSize();
		int len = getTextSize();
		if (len2 != len)
			return false;
		for (int i = 0; i<len; i++)
			if (text[i] != text2[i])
				return false;
		return true;
	};
	shared_ptr<PlaintextSendableData> generateSendableData() override {
		// since ByteArrayPlainText is both a Plaintext and a PlaintextSendableData, 
		// on the one hand it has to implement the generateSendableData() function, 
		// but on the other hand it is in itself an PlaintextSendableData, so we do not really
		// generate sendable data, but just return this object.
		shared_ptr<PlaintextSendableData> res(this);
		return res;
	};

	string toString() override {
		const byte * uc = &(text[0]);
		return string(reinterpret_cast<char const*>(uc), text.size());
	};

	void initFromString(const string & raw) override { 
		text.assign(raw.begin(), raw.end()); }

};

/**
* This class holds the plaintext as a GroupElement.
*/
class GroupElementPlaintext : public Plaintext {
private:
	shared_ptr<GroupElement> element;

public:
	GroupElementPlaintext(shared_ptr<GroupElement> el) { element = el; };
	shared_ptr<GroupElement> getElement() const { return element; };

	bool operator==(const Plaintext &other) const {
		auto temp = dynamic_cast<const GroupElementPlaintext*>(&other);

		return (*(temp->getElement()) == *(this->getElement()));
	};

	shared_ptr<PlaintextSendableData> generateSendableData() override {
		
		return make_shared<GroupElementPlaintextSendableData>(element->generateSendableData());
	}

	// Nested class that holds the sendable data of the outer class
	class GroupElementPlaintextSendableData : public PlaintextSendableData {
	private:
		shared_ptr<GroupElementSendableData>  groupElementData;
	public:
		GroupElementPlaintextSendableData(shared_ptr<GroupElementSendableData> groupElementData) {
			this->groupElementData = groupElementData;
		};

		shared_ptr<GroupElementSendableData> getGroupElement() { return groupElementData; };

		string toString() override {
			return groupElementData->toString();
		};

		void initFromString(const string & row) override {
			groupElementData->initFromString(row);
		}

	};
};

/**
* This is a marker interface. It allows the generation of an AsymmetricCiphertext at an abstract level.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class AsymmetricCiphertextSendableData : public NetworkSerialized {};

/**
* This is a marker interface for all cipher-texts.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class AsymmetricCiphertext {
public:

	/**
	* This function is used when an asymmetric ciphertext needs to be sent via a {@link edu.biu.scapi.comm.Channel} or any other means of sending data (including serialization).
	* It retrieves all the data needed to reconstruct this ciphertext at a later time and/or in a different VM.
	* It puts all the data in an instance of the relevant class that implements the AsymmetricCiphertextSendableData interface.
	* @return the AsymmetricCiphertextSendableData object
	*/
	virtual shared_ptr<AsymmetricCiphertextSendableData> generateSendableData() = 0;
	virtual bool operator==(const AsymmetricCiphertext &other) const = 0;
};

