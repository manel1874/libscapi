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

#include "../include/mid_layer/BiLinearMaps.hpp"

string bigToString(Big x)
{
	ostringstream stream;
	stream << x;
	string str = stream.str();
	return str;
}

/******************/
/* G1Elemenet     */
/******************/
vector<string> G1Element::toStrings()
{
	Big x, y;
	mirElement.g.get(x, y);
	vector<string> res(2);
	res[0] = bigToString(x);
	res[1] = bigToString(y);
	return res; // no worries about return by value - move will take place
}

void G1Element::fromStrings(vector<string> & data) {
	Big x((char *)data[0].c_str());
	Big y((char *)data[1].c_str());
	mirElement.g.set(x, y);
}

void G1Element::hashAndMap(string strToHash, BiLinearMapWrapper & mapper) {
	mapper.pfc.hash_and_map(mirElement, (char*) strToHash.c_str());
}

void G1Element::exponent(biginteger bi, BiLinearMapWrapper & mapper) {
	Big b((char*)bi.str().c_str());
	mapper.pfc.mult(mirElement, b);
}

/******************/
/* G2Elemenet     */
/******************/
vector<string> G2Element::toStrings() {
	vector<string> data(8);
	//ZZn4 zzn4_1, zzn4_2;
	//mirElement.g.get(zzn4_1, zzn4_2);

	//ZZn2 zzn2_1x, zzn2_1y, zzn2_2x, zzn2_2y;
	//zzn4_1.get(zzn2_1x, zzn2_1y);
	//zzn4_2.get(zzn2_2x, zzn2_2y);

	//vector<Big> res(8);
	//zzn2_1x.get(res[0], res[1]);
	//zzn2_1y.get(res[2], res[3]);
	//zzn2_2x.get(res[4], res[5]);
	//zzn2_2y.get(res[6], res[7]);

	//for (int i = 0; i<8; i++)
	//	data[i] = bigToString(res[i]);

	return data;
}

void G2Element::fromStrings(vector<string> & data)
{
	//vector<Big> bigs(8);
	//for (int i = 0; i<8; i++)
	//	bigs[i] = (char *)data[i].c_str();

	//ZZn2 zzn2_1x, zzn2_1y, zzn2_2x, zzn2_2y;

	//zzn2_1x.set(bigs[0], bigs[1]);
	//zzn2_1y.set(bigs[2], bigs[3]);
	//zzn2_2x.set(bigs[4], bigs[5]);
	//zzn2_2y.set(bigs[6], bigs[7]);

	//ZZn4 zzn4x, zzn4y;
	//zzn4x.set(zzn2_1x, zzn2_1y);
	//zzn4y.set(zzn2_2x, zzn2_2y);
	//
	//mirElement.g.set(zzn4x, zzn4y);
}

void G2Element::hashAndMap(string strToHash, BiLinearMapWrapper & mapper) {
	mapper.pfc.hash_and_map(this->mirElement, (char*)strToHash.c_str());
}

void G2Element::exponent(biginteger bi, BiLinearMapWrapper & mapper) {
	Big b((char*)bi.str().c_str());
	mapper.pfc.mult(mirElement, b);
}

/******************/
/* GT             */
/******************/


/**************************/
/* BiLinearMapWrapper     */
/**************************/
GTElement BiLinearMapWrapper::doBilinearMapping(G1Element & g1, G2Element & g2) {
	GTElement res;
	res.mirElement = pfc.pairing(g2.mirElement, g1.mirElement);
	return res;
}
