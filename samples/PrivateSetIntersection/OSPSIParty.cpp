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

#include "OSPSIParty.hpp"

OsPsiParty::OsPsiParty(const OsPsiPartyConfig & config, BiLinearMapWrapper mapper) : 
	m_half_token(mapper)
{
	this->mapper = mapper;
	m_partyId = config.partyId;
	inputFilePath = config.inputFilePath;
	m_sk_private = config.sk_private;
	m_sk = config.sk_public;
	auto res = m_sk / m_sk_private; 	// TODO mod inverse of sk/sk1
	m_half_token.hashAndMap(config.generatorSource);
	m_half_token.exponent(res);

}

void OsPsiParty::run()
{
	read_input();
	encrypt_input();
}

void OsPsiParty::read_input()
{
	ifstream myfile(inputFilePath);
	string line;
	if (myfile.is_open())
	{
		while (getline(myfile, line))
			m_inputs.push_back(line);
		myfile.close();
	}
	else
	{
		cout << "can't open file - exit" << endl;
		exit(-1);
	}
}

void OsPsiParty::encrypt_input()
{
	for (auto i = 0; i<m_inputs.size(); i++)
	{
		G2Element encG2(mapper);
		encG2.hashAndMap(m_inputs[i]);
		encG2.exponent(m_sk);
		m_encrypted_inputs.push_back(encG2);
	}
	//convert all inputs to one string with * delimiter and send it to the server
	//TODO send inputs to the server
}