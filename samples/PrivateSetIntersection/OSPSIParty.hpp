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

#pragma once
#include "../../include/mid_layer/BiLinearMaps.hpp"
#include "../../include/primitives/Prg.hpp"


class OsPsiPartyConfig {
public:
	int partyId;
	const char * generatorSource;
	string inputFilePath;
	biginteger sk_private;
	biginteger sk_public;
	OsPsiPartyConfig(int partyId, string gen, biginteger publicKey, string inputFilePath) {
		this->partyId = partyId;
		this->generatorSource = gen.c_str();
		this->inputFilePath = inputFilePath;
		PrgFromOpenSSLAES prg;
		SecretKey key = prg.generateKey(128);
		prg.setKey(key);
		sk_private = 10; //prg.getRandom64();
		sk_public = publicKey;
	}
};

class OsPsiParty
{
public:
	OsPsiParty(const OsPsiPartyConfig & config, BiLinearMapWrapper mapper);
	void run();
	vector<G2Element> getEncryptedInputs() { return m_encrypted_inputs; };
	G1Element getHalfToken() { return m_half_token; };

private:
	BiLinearMapWrapper mapper;
	int mode;
	int m_partyId;
	string inputFilePath;
	biginteger m_sk;
	biginteger m_sk_private;
	G1Element m_half_token;
	vector<string> m_inputs;
	vector<G2Element> m_encrypted_inputs;
	void read_input();
	void encrypt_input();
};

