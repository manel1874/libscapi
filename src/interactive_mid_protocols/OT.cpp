#include "../../include/interactive_mid_protocols/OT.hpp"

string OTRGroupElementPairMsg::toString() {
	return h0->toString() + ":" + h1->toString();
}
void OTRGroupElementPairMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 2 || size == 4);
	if (size == 2) {
		h0 = make_shared<ZpElementSendableData>(0);
		h1 = make_shared<ZpElementSendableData>(0);
		h0->initFromString(str_vec[0]);
		h1->initFromString(str_vec[1]);
	} else {
		h0 = make_shared<ECElementSendableData>(0,0);
		h1 = make_shared<ECElementSendableData>(0,0);
		h0->initFromString(str_vec[0] + ":" + str_vec[1]);
		h1->initFromString(str_vec[2] + ":" + str_vec[3]);
	}

}

string OTRGroupElementQuadMsg::toString() {
	return x->toString() + ":" + y->toString() + ":" + z0->toString() + ":" + z1->toString();
}
void OTRGroupElementQuadMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 4 || size == 8);
	if (size == 4) {
		x = make_shared<ZpElementSendableData>(0);
		y = make_shared<ZpElementSendableData>(0);
		z0 = make_shared<ZpElementSendableData>(0);
		z1 = make_shared<ZpElementSendableData>(0);
		x->initFromString(str_vec[0]);
		y->initFromString(str_vec[1]);
		z0->initFromString(str_vec[2]);
		z1->initFromString(str_vec[3]);
	}
	else {
		x = make_shared<ECElementSendableData>(0, 0);
		y = make_shared<ECElementSendableData>(0, 0);
		z0 = make_shared<ECElementSendableData>(0, 0);
		z1 = make_shared<ECElementSendableData>(0, 0);
		x->initFromString(str_vec[0] + ":" + str_vec[1]);
		y->initFromString(str_vec[2] + ":" + str_vec[3]);
		z0->initFromString(str_vec[4] + ":" + str_vec[5]);
		z1->initFromString(str_vec[6] + ":" + str_vec[7]);
	}
}

string OTOnGroupElementSMsg::toString() {
	return w0->toString() + ":" + w1->toString() + ":" + c0->toString() + ":" + c1->toString();
}
void OTOnGroupElementSMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 4 || size == 8);
	if (size == 4) {
		w0 = make_shared<ZpElementSendableData>(0);
		w1 = make_shared<ZpElementSendableData>(0);
		c0 = make_shared<ZpElementSendableData>(0);
		c1 = make_shared<ZpElementSendableData>(0);
		w0->initFromString(str_vec[0]);
		w1->initFromString(str_vec[1]);
		c0->initFromString(str_vec[2]);
		c1->initFromString(str_vec[3]);
	}
	else {
		w0 = make_shared<ECElementSendableData>(0, 0);
		w1 = make_shared<ECElementSendableData>(0, 0);
		c0 = make_shared<ECElementSendableData>(0, 0);
		c1 = make_shared<ECElementSendableData>(0, 0);
		w0->initFromString(str_vec[0] + ":" + str_vec[1]);
		w1->initFromString(str_vec[2] + ":" + str_vec[3]);
		c0->initFromString(str_vec[4] + ":" + str_vec[5]);
		c1->initFromString(str_vec[6] + ":" + str_vec[7]);
	}
}

string OTOnByteArraySMsg::toString() {
	string output = w0->toString() + ":" + w1->toString() + ":";
	const byte * uc = &(c0[0]);
	output += string(reinterpret_cast<char const*>(c0.data()), c0.size());
	output += ":";
	output += string(reinterpret_cast<char const*>(c1.data()), c1.size());
	return output;
}

void OTOnByteArraySMsg::initFromString(const string & row) {
	auto str_vec = explode(row, ':');
	int size = str_vec.size();
	assert(size == 4 || size == 6);
	if (size == 4) {
		w0 = make_shared<ZpElementSendableData>(0);
		w1 = make_shared<ZpElementSendableData>(0);
		w0->initFromString(str_vec[0]);
		w1->initFromString(str_vec[1]);
		c0.assign(str_vec[2].begin(), str_vec[2].end());
		c1.assign(str_vec[3].begin(), str_vec[3].end());
	}
	else {
		w0 = make_shared<ECElementSendableData>(0, 0);
		w1 = make_shared<ECElementSendableData>(0, 0);
		w0->initFromString(str_vec[0] + ":" + str_vec[1]);
		w1->initFromString(str_vec[2] + ":" + str_vec[3]);
		c0.assign(str_vec[4].begin(), str_vec[4].end());
		c1.assign(str_vec[5].begin(), str_vec[5].end());
	}
}