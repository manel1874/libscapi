/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#include "../../include/primitives/HashOpenSSL.hpp"

OpenSSLHash::OpenSSLHash(string hashName) {
	//Instantiates a hash object in OpenSSL. We keep a pointer to the created hash object in c++.
	//Remember to delete it using the finalize method.
	EVP_MD_CTX* mdctx;
	const EVP_MD *md;
	
	OpenSSL_add_all_digests();

	//Get the string from java.
	const char* name = hashName.c_str();

	// Get the OpenSSL digest.
	md = EVP_get_digestbyname(name);
	if (md == 0)
		throw runtime_error("failed to create hash");

	// Create an OpenSSL EVP_MD_CTX struct and initialize it with the created hash.
	mdctx = EVP_MD_CTX_create();
	if (0 == (EVP_DigestInit(mdctx, md)))
		throw runtime_error("failed to create hash");

	hash = mdctx;
	hashSize = EVP_MD_CTX_size(hash);
}

OpenSSLHash::~OpenSSLHash() {
	EVP_MD_CTX_destroy(hash);
}

string OpenSSLHash::getAlgorithmName() {
	int type = EVP_MD_CTX_type(hash);
	const char* name = OBJ_nid2sn(type);
	return string(name);
}


void OpenSSLHash::update(const vector<byte> &in, int inOffset, int inLen){
	//Check that the offset and length are correct.
	if ((inOffset > (int)in.size()) || (inOffset + inLen > (int)in.size()) || (inOffset<0))
		throw out_of_range("wrong offset for the given input buffer");
	if (inLen < 0)
		throw invalid_argument("wrong length for the given input buffer");
	if (inLen == 0)
		throw new out_of_range("wrong length for the given input buffer");

	//The dll function does the update from offset 0.
	//If the given offset is greater than 0, copy the relevant bytes to a new array and send it to the dll function.
	byte * input = new byte[inLen];
	copy_byte_vector_to_byte_array(in, input, inOffset);

	// Update the hash with the message.
	EVP_DigestUpdate(hash, input, inLen);
}

void OpenSSLHash::hashFinal(vector<byte> &out, int outOffset) {

	//Checks that the offset and length are correct.
	if (outOffset<0)
		throw new out_of_range("wrong offset for the given output buffer");

	int length = EVP_MD_CTX_size(hash);
	byte* tempOut = new byte[length];
	EVP_DigestFinal_ex(hash, tempOut, NULL);
	//Initialize the hash structure again to enable repeated calls.
	EVP_DigestInit(hash, EVP_MD_CTX_md(hash));
	copy_byte_array_to_byte_vector(tempOut, length, out, outOffset);
	delete tempOut;
}

CryptographicHash* CryptographicHash::get_new_cryptographic_hash(string hashName)
{
	set<string> algSet = { "SHA1", "SHA224", "SHA256", "SHA384", "SHA512" };
	if (algSet.find(hashName) == algSet.end())
		throw invalid_argument("unexpected hash_name");
	return new OpenSSLHash(hashName);
}