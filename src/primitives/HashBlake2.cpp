#include "../../include/primitives/HashBlake2.hpp"

Blake2Hash::Blake2Hash(int hashBytesSize) : hashSize(hashBytesSize) {
	blake2b_init(S, hashBytesSize);
}

void Blake2Hash::update(const vector<byte> &in, int inOffset, int inLen) {
	blake2b_update(S, (const uint8_t *)in.data() + inOffset, inLen);
}

void Blake2Hash::hashFinal(vector<byte> &out, int outOffset) {
	if (out.size() < outOffset + hashSize) {
		out.resize(outOffset + hashSize);
	}
	blake2b_final(S, out.data() + outOffset, hashSize);
	blake2b_init(S, hashSize);
}