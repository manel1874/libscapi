#include "../include/primitives/Prg.hpp"
#include <iostream>

int mainPrg()
{
	//make sure that 2 prg with different secret key dont give the same randoms

	cout << "in prg main" << endl;

	OpenSSLRC4 rc4;
	//auto start = scapi_now();
	prgFromOpenSSLAES random4;// (10000, false);
							  //print_elapsed_ms(start, "creating 12800 random prg");
							  //prgFromOpenSSLAES random5;


							  //start = scapi_now();
							  //auto sk1 = random4.generateKey(16);
							  //print_elapsed_ms(start, "generate key");

							  //start = scapi_now();
							  //random4.setKey(sk1);
							  //print_elapsed_ms(start, "set key");


	return 0;
}
