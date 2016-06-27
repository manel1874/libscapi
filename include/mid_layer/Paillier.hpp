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
#include "AsymmetricEnc.hpp"
#include "../infra/Common.hpp"
#include "../infra/NTLWrapper.hpp"
#include "../infra/MathAlgorithms.hpp"
//#include "gmp.h"
//#include "gmpxx.h"
//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
//#include <sstream>
#include <NTL/ZZ.h>
//#include "/home/liork/NTLWrapper/MPZPrecomputeExp_Sec.h"

//using namespace NTL;

/******
 TYPES
*******/

struct paillier_pubkey_t
{
	int bits;  /* e.g., 1024 */
	//mpz_t n;   /* public modulus n = p q */
	//mpz_t n_squared; /* cached to avoid recomputing */
	//mpz_t n_plusone; /* cached to avoid recomputing */
	biginteger n;   /* public modulus n = p q */
	biginteger n_squared; /* cached to avoid recomputing */
	biginteger n_plusone; /* cached to avoid recomputing */
	NTL::ZZ *g; /* cached to avoid recomputing */
};


struct paillier_prvkey_t
{
	//mpz_t lambda;    /* lambda(n), i.e., lcm(p-1,q-1) */
	//mpz_t x;   /* cached to avoid recomputing */
	biginteger lambda;
	biginteger x;
};

struct paillier_plaintext_t
{
	//mpz_t m;
	biginteger m;
};


struct paillier_ciphertext_t
{
	//mpz_t c;
	biginteger c;
};

typedef void (*paillier_get_rand_t) ( void* buf, int len );

#define PAILLIER_BITS_TO_BYTES(n) ((n) % 8 ? (n) / 8 + 1 : (n) / 8)

class PaillierAPI
{

public:

	//void init_rand(gmp_randstate_t rand, paillier_get_rand_t get_ran, int bytes);
	void complete_pubkey( paillier_pubkey_t* pub );
	void complete_prvkey( paillier_prvkey_t* prv, paillier_pubkey_t* pub );
	void paillier_keygen( int modulusbits, paillier_pubkey_t **pub, 
		paillier_prvkey_t **prv, paillier_get_rand_t get_rand );

	 paillier_ciphertext_t* paillier_enc( paillier_ciphertext_t* res,
						 paillier_pubkey_t* pub,
						 paillier_plaintext_t* pt,
						 paillier_get_rand_t get_rand );

	paillier_plaintext_t* paillier_dec( paillier_plaintext_t* res,
										paillier_pubkey_t* pub,
										paillier_prvkey_t* prv,
										paillier_ciphertext_t* ct );

	void paillier_mul( paillier_pubkey_t* pub,
					   paillier_ciphertext_t* res,
					   paillier_ciphertext_t* ct0,
					   paillier_ciphertext_t* ct1 );

	void paillier_exp(paillier_pubkey_t* pub,
					paillier_ciphertext_t* res,
					paillier_ciphertext_t* ct,
					paillier_plaintext_t* pt );

	paillier_plaintext_t* paillier_plaintext_from_ui( unsigned long int x );
	paillier_plaintext_t* paillier_plaintext_from_bytes( void* m, int len );
	paillier_plaintext_t* paillier_plaintext_from_str( char* str );
	char* paillier_plaintext_to_str( paillier_plaintext_t* pt );
	void* paillier_plaintext_to_bytes( int len, paillier_plaintext_t* pt );
	paillier_ciphertext_t* paillier_ciphertext_from_bytes( void* c, int len );
	void* paillier_ciphertext_to_bytes( int len, paillier_ciphertext_t* ct );
	char* paillier_pubkey_to_hex( paillier_pubkey_t* pub );
	char* paillier_prvkey_to_hex( paillier_prvkey_t* prv );
	paillier_pubkey_t* paillier_pubkey_from_hex( char* str );
	paillier_prvkey_t* paillier_prvkey_from_hex( char* str, paillier_pubkey_t* pub );
	void paillier_freepubkey( paillier_pubkey_t* pub );
	void paillier_freeprvkey( paillier_prvkey_t* prv );
	void paillier_freeplaintext( paillier_plaintext_t* pt );
	void paillier_freeciphertext( paillier_ciphertext_t* ct );
	void paillier_get_rand_devrandom(  void* buf, int len );
	void paillier_get_rand_devurandom( void* buf, int len );
	paillier_ciphertext_t* paillier_create_enc_zero();
	void paillier_get_rand_file( void* buf, int len, char* file );
	void convertZZtoMpz(NTL::ZZ zz, biginteger & p);//mpz_t &p);
	NTL::ZZ convertMpztoZZ(biginteger & p); //mpz_t &p);
};


