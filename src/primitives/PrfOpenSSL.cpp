#include "../../include/primitives/PrfOpenSSL.hpp"
#include <algorithm>

/*************************************************/
/**** OpenSSLPRP ***/
/*************************************************/

SecretKey OpenSSLPRP::generateKey(int keySize) {
	byte * buf = new byte[keySize];
	if (!RAND_bytes(buf, keySize))
		throw runtime_error("key generation failed");
	vector<byte> vec;
	copy_byte_array_to_byte_vector(buf, keySize, vec, 0);
	SecretKey sk(vec, getAlgorithmName());
	delete buf;
	return sk;
}

void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offset and length are correct.
	if ((inOff > inBytes.size()) || (inOff + getBlockSize() > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	//if ((outOff > outBytes.size()) || (outOff + getBlockSize() > outBytes.size()))
	//	throw out_of_range("wrong offset for the given output buffer");

	const byte* input = & inBytes[inOff];
	
	int size;
	int blockSize = getBlockSize();
	// allocate a new byte array with the size of the specific prp algorithm.
	byte* ret = new byte[getBlockSize()];

	// compute the prp on the given input array, put the result in ret.
	EVP_EncryptUpdate(computeP, ret, &size, input, blockSize);

	// put the result of the final computation in the output vector.
	copy_byte_array_to_byte_vector(ret, size, outBytes, 0);
	delete ret;
}

void OpenSSLPRP::optimizedCompute(const vector<byte> & inBytes, vector<byte> &outBytes) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inBytes.size() % getBlockSize()) != 0)
		throw out_of_range("inBytes should be aligned to the block size");
	if (outBytes.size() != inBytes.size())
		throw out_of_range("outBytes and inBytes must be in the same size");

	// calculate the number of blocks in the given input array.
	int size = inBytes.size();
	// allocate a new byte array with the block size of the specific prp algorithm.
	byte* outBlock = new byte[size];

	// compute the prp on each block and put the result in the output array.
	EVP_EncryptUpdate(computeP, outBlock, &size, &inBytes[0], size);
	copy_byte_array_to_byte_vector(outBlock, size, outBytes, 0);
	delete (outBlock);
}

void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// the checks on the offset and length are done in the computeBlock(inBytes, inOff, outBytes, outOff).
	if (inLen == outLen && inLen == getBlockSize()) //Checks that the lengths are the same as the block size.
		computeBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");
}


void OpenSSLPRP::computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// the checks on the offset and length is done in the computeBlock (inBytes, inOffset, outBytes, outOffset).
	if (inLen == getBlockSize()) //Checks that the input length is the same as the block size.
		computeBlock(inBytes, inOffset, outBytes, outOffset);
	else
		throw out_of_range("Wrong size");
}

void OpenSSLPRP::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// Checks that the offsets are correct. 
	if ((inOff > inBytes.size()) || (inOff + getBlockSize() > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	if ((outOff > outBytes.size()) || (outOff + getBlockSize() > outBytes.size()))
		throw out_of_range("wrong offset for the given output buffer");

	// allocate a new byte array with the size of the specific prp algorithm.
	byte* ret = new byte[outBytes.size()];
	int size;

	//Invert the prp on the given input array, put the result in ret.
	EVP_DecryptUpdate(invertP, ret, &size, &inBytes[inOff], getBlockSize());
	copy_byte_array_to_byte_vector(ret, size, outBytes, 0);
	delete ret;
}

void OpenSSLPRP::optimizedInvert(const vector<byte> & inBytes, vector<byte> &outBytes) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	if ((inBytes.size() % getBlockSize()) != 0) 
		throw out_of_range("inBytes should be aligned to the block size");
	if (outBytes.size() != inBytes.size())
		throw out_of_range("outBytes and inBytes must be in the same size");

	// calculate the number of blocks in the given input array.
	int size = inBytes.size();
	// allocate a new byte array with the block size of the specific prp algorithm.
	byte* outBlock = new byte[size];
	
	// compute the prp on each block and put the result in the output array.
	EVP_DecryptUpdate(invertP, outBlock, &size, &inBytes[0], size);
	copy_byte_array_to_byte_vector(outBlock, size, outBytes, 0);
	delete (outBlock);
}

void OpenSSLPRP::invertBlock(const vector<byte> & inBytes, int inOff, vector<byte>& outBytes, int outOff, int len) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// the checks of the offset and lengths are done in the invertBlock(inBytes, inOff, outBytes, outOff)
	if (len == getBlockSize()) //Checks that the length is the same as the block size
		invertBlock(inBytes, inOff, outBytes, outOff);
	else
		throw out_of_range("Wrong size");
}

OpenSSLPRP::~OpenSSLPRP() {
	EVP_CIPHER_CTX_cleanup(computeP);
	EVP_CIPHER_CTX_cleanup(invertP);
	EVP_CIPHER_CTX_free(computeP);
	EVP_CIPHER_CTX_free(invertP);
}

/*************************************************/
/**** OpenSSLAES ***/
/*************************************************/

OpenSSLAES::OpenSSLAES() {
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();
}

void OpenSSLAES::setKey(SecretKey secretKey) {
	auto keyVec = secretKey.getEncoded();
	int len = keyVec.size();
	// AES key size should be 128/192/256 bits long.
	if (len != 16 && len != 24 && len != 32)
		throw InvalidKeyException("AES key size should be 128/192/256 bits long");

	// set the key to the native objects.
	byte* keyBytes = &keyVec[0];
	int bitLen = len * 8; //number of bits in key.

	// create the requested block cipher.
	const EVP_CIPHER* cipher;
	switch (bitLen) {
	case 128: cipher = EVP_aes_128_ecb();
		break;
	case 192: cipher = EVP_aes_192_ecb();
		break;
	case 256: cipher = EVP_aes_256_ecb();
		break;
	default: break;
	}

	// initialize the AES objects with the key.
	EVP_EncryptInit(computeP, cipher, keyBytes, NULL);
	EVP_DecryptInit(invertP, cipher, keyBytes, NULL);

	// set the AES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);

	_isKeySet = true;
}

/*************************************************/
/**** OpenSSLHMAC ***/
/*************************************************/
void OpenSSLHMAC::construct(string hashName) {
	/*
	* The way we call the hash is not the same as OpenSSL. For example: we call "SHA-1" while OpenSSL calls it "SHA1".
	* So the hyphen should be deleted.
	*/

	hmac = new  HMAC_CTX;
	OpenSSL_add_all_digests();
	HMAC_CTX_init(hmac);

	hashName.erase(remove(hashName.begin(), hashName.end(), '-'), hashName.end());
	// get the underlying hash function.
	const EVP_MD *md = EVP_get_digestbyname(hashName.c_str());

	// create an Hmac object and initialize it with the created hash and default key.
	int res = HMAC_Init_ex(hmac, "012345678", 0, md, NULL);
	//res = HMAC_Init_ex(hmac, NULL, 0, md, NULL);
	if (0 == res)
		throw runtime_error("failed to create hmac");

	this->random = get_seeded_random();
}

void OpenSSLHMAC::setKey(SecretKey secretKey) {
	// initialize the Hmac object with the given key.
	auto secVec = secretKey.getEncoded();
	HMAC_Init_ex(hmac, &secVec[0], secVec.size(), NULL, NULL);
	_isKeySet = true;
}

string OpenSSLHMAC::getAlgorithmName() {
	int type = EVP_MD_type(hmac->md);
	// convert the type to a name.
	const char* name = OBJ_nid2sn(type);
	return "Hmac/" + string(name);
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOff, vector<byte> &outBytes, int outOff) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	throw out_of_range("Size of input is not specified");
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOff, int inLen, vector<byte> &outBytes, int outOff, int outLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");

	// the checks of the offsets and lengths are done in the conputeBlock (inBytes, inOff, inLen, outBytes, outOff).
	// make sure the output size is correct
	if (outLen == getBlockSize())
		computeBlock(inBytes, inOff, inLen, outBytes, outOff);
	else
		throw out_of_range("Output size is incorrect");
}

void OpenSSLHMAC::computeBlock(const vector<byte> & inBytes, int inOffset, int inLen, vector<byte> &outBytes, int outOffset) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	
	// check that the offset and length are correct.
	if ((inOffset > inBytes.size()) || (inOffset + inLen > inBytes.size()))
		throw out_of_range("wrong offset for the given input buffer");
	//if ((outOffset > outBytes.size()) || (outOffset + getBlockSize() > outBytes.size()))
	//	throw out_of_range("wrong offset for the given output buffer");

	// update the Hmac object.
	HMAC_Update(hmac, &inBytes[inOffset], inLen);

	int size = EVP_MD_size(hmac->md); // Get the size of the hash output.
	byte* output = new byte[size]; // create a byte array to hold the result.

	//Compute the final function and copy the output the the given output array
	if (0 == (HMAC_Final(hmac, output, NULL)))
		delete output;

	copy_byte_array_to_byte_vector(output, size, outBytes, 0);
	delete(output);

	// initialize the Hmac again in order to enable repeated calls.
	if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
		throw runtime_error("failed to init hmac object");
}

SecretKey OpenSSLHMAC::generateKey(int keySize) {
	// generate a random string of bits of length keySize, which has to be greater that zero. 

	// if the key size is zero or less - throw exception.
	if (keySize <= 0)
		throw invalid_argument("key size must be greater than 0");

	// the key size has to be a multiple of 8 so that we can obtain an array of random bytes which we use
	// to create the SecretKey.
	if ((keySize % 8) != 0)
		throw invalid_argument("Wrong key size: must be a multiple of 8");

	byte* genBytes = new byte[keySize / 8]; // creates a byte array of size keySize.
	RAND_bytes(genBytes, keySize / 8);	// generates the bytes using the random.
	return SecretKey(genBytes, keySize/8, "");
}

vector<byte> OpenSSLHMAC::mac(const vector<byte> &msg, int offset, int msgLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// creates the tag.
	vector<byte> tag(getMacSize());
	// computes the hmac operation.
	computeBlock(msg, offset, msgLen, tag, 0);
	//Returns the tag.
	return tag;
}

bool OpenSSLHMAC::verify(const vector<byte> &msg, int offset, int msgLength, vector<byte>& tag) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	// if the tag size is not the mac size - returns false.
	if (tag.size() != getMacSize())
		return false;
	// calculates the mac on the msg to get the real tag.
	vector<byte> macTag = mac(msg, offset, msgLength);

	// compares the real tag to the given tag.
	// for code-security reasons, the comparison is fully performed. that is, even if we know already after the first few bits 
	// that the tag is not equal to the mac, we continue the checking until the end of the tag bits.
	bool equal = true;
	int length = macTag.size();
	for (int i = 0; i<length; i++) {
		if (macTag[i] != tag[i]) {
			equal = false;
		}
	}
	return equal;
}

void OpenSSLHMAC::update(vector<byte> & msg, int offset, int msgLen) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");

	// update the Hmac object.
	HMAC_Update(hmac, &msg[offset], msgLen);
}

void OpenSSLHMAC::doFinal(vector<byte> & msg, int offset, int msgLength, vector<byte> & tag_res) {
	if (!isKeySet())
		throw IllegalStateException("secret key isn't set");
	
	// updates the last msg block.
	update(msg, offset, msgLength);
	// creates the tag.
	byte* tag = new byte[getMacSize()];

	// compute the final function and copy the output the the given output array
	if (0 == (HMAC_Final(hmac, tag, NULL)))
		delete tag;

	//initialize the Hmac again in order to enable repeated calls.
	if (0 == (HMAC_Init_ex(hmac, hmac->key, hmac->key_length, hmac->md, NULL)))
		delete(tag);

	copy_byte_array_to_byte_vector(tag, getMacSize(), tag_res, 0);
	// release the allocated memory.
	delete tag;
}

OpenSSLHMAC::~OpenSSLHMAC()
{
	HMAC_CTX_cleanup(hmac);
}

/*************************************************/
/**** OpenSSLTripleDES ***/
/*************************************************/

OpenSSLTripleDES::OpenSSLTripleDES() {
	// create the native objects.
	computeP = EVP_CIPHER_CTX_new();
	invertP = EVP_CIPHER_CTX_new();
}

void OpenSSLTripleDES::setKey(SecretKey secretKey) {
	vector<byte> keyBytesVector = secretKey.getEncoded();
	int len = keyBytesVector.size();

	// tripleDES key size should be 128/192 bits long
	if (len != 16 && len != 24)
		throw InvalidKeyException("TripleDES key size should be 128/192 bits long");

	// create the requested block cipher.
	const EVP_CIPHER* cipher = EVP_des_ede3();

	// initialize the Triple DES objects with the key.
	EVP_EncryptInit(computeP, cipher, &keyBytesVector[0], NULL);
	EVP_DecryptInit(invertP, cipher, &keyBytesVector[0], NULL);

	// set the Triple DES objects with NO PADDING.
	EVP_CIPHER_CTX_set_padding(computeP, 0);
	EVP_CIPHER_CTX_set_padding(invertP, 0);
	_isKeySet= true;
}

PseudorandomFunction* PseudorandomFunction::get_new_prf(string algName) {
	if (algName == "AES")
		return new OpenSSLAES();
	if (algName == "TripleDES")
		return new OpenSSLTripleDES();
	if (algName == "HMAC")
		return new OpenSSLHMAC();
	// wrong algorithm name
	throw invalid_argument("unexpected prf name");
}