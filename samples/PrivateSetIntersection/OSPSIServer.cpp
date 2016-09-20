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
#include "OSPSIServer.hpp"

OsPsiServer::OsPsiServer(OsPsiParty &party0, OsPsiParty &party1) : 
	m_token(G1Element(bilinearMapper), G1Element(bilinearMapper))
{
	m_clientInputs[0] = party0.getEncryptedInputs();
	m_clientInputs[1] = party1.getEncryptedInputs();
	m_token = pair<G1Element, G1Element>(party0.getHalfToken(), party1.getHalfToken());
}

void OsPsiServer::run()
{
	cout << "calculating intersection " << endl;
	calculate_intersection_indexes(0, 1);
}

void OsPsiServer::calculate_intersection_indexes(int clientId1, int clientId2)
{
	vector<GTElement> client1Mappings;
	vector<GTElement> client2Mappings;
	do_bilinear_mapping(client1Mappings, m_clientInputs[clientId1], m_token.first);
	do_bilinear_mapping(client2Mappings, m_clientInputs[clientId2], m_token.second);
	auto intersected_indices = find_intersection(client1Mappings, client2Mappings);
	for (auto idx1 = 0; idx1<intersected_indices.first.size(); idx1++)
	{
		cout << "instersection at idx1 : " << intersected_indices.first[idx1]
			<< " and at idx2 : " << intersected_indices.second[idx1] << endl;
	}
}

void OsPsiServer::do_bilinear_mapping(vector<GTElement> & target, 
	vector<G2Element> & source, G1Element token)
{
	auto t1 = scapi_now();
	for (auto g2 : source)
	{
		auto pairing_res = bilinearMapper.doBilinearMapping(token, g2);
		target.push_back(pairing_res);
	}
	print_elapsed_ms(t1, "biliniar mapping");
}

pair<vector<int>, vector<int>> OsPsiServer::find_intersection(
	vector<GTElement> & target1, vector<GTElement> & target2)
{
	auto t1 = scapi_now();
	pair<vector<int>, vector<int>> res;

	for (auto idx1 = 0; idx1<target1.size(); idx1++)
	{
		for (auto idx2 = 0; idx2<target2.size(); idx2++)
		{

			if (target1[idx1] == target2[idx2])
			{
				res.first.push_back(idx1);
				res.second.push_back(idx2);
			}
		}
	}
	print_elapsed_ms(t1, "intersection");
	return res;
}

