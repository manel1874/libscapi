#pragma once
#include "../primitives/Dlog.hpp"

class KeySendableData : public NetworkSerialized {};

class ElGamalPublicKeySendableData : public KeySendableData {
private:
	shared_ptr<GroupElementSendableData> c;

public:
	ElGamalPublicKeySendableData(shared_ptr<GroupElementSendableData> c) {
		this->c = c;
	}

	shared_ptr<GroupElementSendableData> getC() { return c; }

	string toString() {
		return c->toString();
	}

	void initFromString(const string & raw) {
		c->initFromString(raw);
	}
};

/**
* This class represents a Public Key suitable for the El Gamal Encryption Scheme. Although the constructor is public, it should only be instantiated by the
* Encryption Scheme itself via the generateKey function.
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class ElGamalPublicKey {

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
};

