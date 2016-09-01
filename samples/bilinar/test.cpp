#include <iostream>
#include <ctime>
#define MR_PAIRING_BLS    // AES-256 security
#define AES_SECURITY 256
#include "pairing_3.h"

using namespace std;

/**
* Test method to demonstrate bilinear maps
* g1 in G1 and g2 in G2. And a biliniear map e:G1xG2-->Gt
* a and b are Big numbers.
* Computing and verifying that: e(g1^a,g2^b)=(e(g1,g2))^ab
*/
int main()
{
	auto st1 = "StringForG1"; // will be mapped to G1
	auto st2 = "StringForG2"; // will be mapped to G2
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	G1 g1, g1PowA;
	G2 g2, g2PowB;
	GT res, res2, res3;
	Big a,b;

	// map the strings to g1 and g2
	pfc.hash_and_map(g1, (char *)st1);
	pfc.hash_and_map(g2, (char *)st2);

	cout << "mapped string to g1 and g2.\ng1:" << g1.g << "\n\ng2:" << g2.g << endl;

	a = 300;
	b = 5321;
	g1PowA = pfc.mult(g1,a);
	g2PowB = pfc.mult(g2,b);
	cout << "\n\ng1^a=" << g1PowA.g << "\ng2^b=" << g2PowB.g << endl;

	res = pfc.pairing(g2PowB, g1PowA); // res = e(g2^b, g1^a)
	cout << "\n\ne(g2^b, g1^a)= " << res.g << endl;

	res2 = pfc.pairing(g2, g1); // res = e(g1, g2)
	cout << "\n\ne(g2, g1)= " << res2.g << endl;

	res3 = pfc.power(res2, a*b); // res3 = [e(g1, g2)]^ab
	cout << "\n\ne(g2, g1)^ab= " << res3.g << endl;

	auto equal_res = (res == res3);
	auto s_eq = equal_res? "Yes!" : "No :(";
	cout << "\n\n*************\ntest showed equal? " << s_eq << "\n********************\n";
	
	
	return 0;
}

void func() {
	PFC pfc(AES_SECURITY);  // initialise pairing-friendly curve
	time_t seed;
        G1 Alice,Bob,sA,sB;
    	G2 B6,Server,sS;
        GT res,sp,ap,bp;
        Big ss,s,a,b;

    	time(&seed);
	irand((long)seed);
	pfc.random(ss);    // TA's super-secret
	
	cout << "Mapping Server ID to point" << endl;
        pfc.hash_and_map(Server,(char *)"Server");

	cout << "Mapping Alice & Bob ID's to points" << endl;
	pfc.hash_and_map(Alice,(char *)"Alice");
	pfc.hash_and_map(Bob,(char *)"Robert");

	cout << "Alice, Bob and the Server visit Trusted Authority" << endl;

	sS=pfc.mult(Server,ss);
        sA=pfc.mult(Alice,ss);
	sB=pfc.mult(Bob,ss);

    	cout << "Alice and Server Key Exchange" << endl;


    	pfc.random(a);  // Alice's random number
    	pfc.random(s);   // Server's random number

        res=pfc.pairing(Server,sA);

        if (!pfc.member(res))
    	{
       		 cout << "Wrong group order - aborting" << endl;
	       	 exit(0);
	}

        ap=pfc.power(res,a);

        res=pfc.pairing(sS,Alice);

        if (!pfc.member(res))
	{
        	cout << "Wrong group order - aborting" << endl;
	        exit(0);
	}

        sp=pfc.power(res,s);

	cout << "Alice  Key= " << pfc.hash_to_aes_key(pfc.power(sp,a)) << endl;
	cout << "Server Key= " << pfc.hash_to_aes_key(pfc.power(ap,s)) << endl;

	cout << "Bob and Server Key Exchange" << endl;

	pfc.random(b);   // Bob's random number
	pfc.random(s);   // Server's random number

        res=pfc.pairing(Server,sB);
   	if (!pfc.member(res))
	{
        	cout << "Wrong group order - aborting" << endl;
        	exit(0);
	}
 	bp=pfc.power(res,b);

        res=pfc.pairing(sS,Bob);
    	if (!pfc.member(res))
    	{
        	cout << "Wrong group order - aborting" << endl;
	        exit(0);
	}

    	sp=pfc.power(res,s);

    	cout << "Bob's  Key= " << pfc.hash_to_aes_key(pfc.power(sp,b)) << endl;
    	cout << "Server Key= " << pfc.hash_to_aes_key(pfc.power(bp,s)) << endl;

	cout << "done!" << endl;
}

