#pragma once

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


#ifndef SCAPI_HASH_BLAKE2_H
#define SCAPI_HASH_BLAKE2_H

#include "Hash.hpp"
#include <BLAKE2/sse/blake2.h>

/**
* A general adapter class of hash for Blake 2. <p>
* This class implements all the functionality by passing requests to the adaptee library.
*
*/
class Blake2Hash : public virtual CryptographicHash {
private:
	blake2b_state S[1];
	int hashSize;
protected:
public:
	/**
	* Constructs the native hash function using BLAKE2 library.
	* @param hashName - the name of the hash. This will be passed to the jni dll function createHash so it will know which hash to create.
	*/
	Blake2Hash(int hashBytesSize);
	int getHashedMsgSize() override { return hashSize; }
	string getAlgorithmName() override { return "BLAKE2"; }
	void update(const vector<byte> &in, int inOffset, int inLen) override;
	void hashFinal(vector<byte> &out, int outOffset) override;
};

#endif
