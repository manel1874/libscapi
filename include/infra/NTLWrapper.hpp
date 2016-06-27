#pragma once

#define ZERO 0
#define ONE 1
#define TWO 2

#include <NTL/ZZ.h>

class NTLWrapper {
public:
	NTLWrapper();
	void init(const NTL::ZZ &p, const NTL::ZZ &q, const int n);
	void getGenerators(NTL::ZZ *generators, const int n);
	void randomZp(NTL::ZZ &random);
	void randomKey(NTL::ZZ &random);
	void powerZp(NTL::ZZ &result, const NTL::ZZ &b, const NTL::ZZ &e);
	void multiplyZp(NTL::ZZ &result, const NTL::ZZ &a, const NTL::ZZ &b);
	void inverseZp(NTL::ZZ &result, const NTL::ZZ &a);
	void sumZp(NTL::ZZ &result, const NTL::ZZ &a, const NTL::ZZ &b);
	void subtractZp(NTL::ZZ &result, const NTL::ZZ &a, const NTL::ZZ &b);
	void extractRoot(NTL::ZZ &root, const NTL::ZZ &squared);
	bool getLSB(const NTL::ZZ &element);
private:
	NTL::ZZ m_p;
	NTL::ZZ m_q;
	int m_n;
};


#endif //NTLWRAPPER_NTLWRAPPER_H
