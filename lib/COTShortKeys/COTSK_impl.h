#ifndef COTSHORTKEYS_H___
#define COTSHORTKEYS_H___

#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"
#include "../../include/primitives/Prg.hpp"
#include "transpose.h"
#include "gf2x_util.h"
//#define DEBUG_PRINT

/*
    HELPER METHODS   
*/

const byte BITMASK[8] = { 0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80 };
const uint32_t MOD_MASK = 7; // 0x0...111
inline byte index(const byte *v, const uint32_t & ind) {  return v[ind >> 3] & BITMASK[ind & MOD_MASK]; } 
inline uint32_t CEIL8 (uint32_t n) { return( 8*((n-1)/8) + 8);  }

/*********************************************
    CLASS DEFINITION - COTSK_BASE
**********************************************/
class COTSK_Base {

	public:
	
	COTSK_Base(int baseOTport, const shared_ptr<CommParty> & channel ,uint32_t L, uint32_t K, uint32_t M, uint32_t sizeof_s) { 
		_L = L; 
		_K = K; 
		_M = M;
		 assert(M % 8 == 0);
		
		_L_CEIL8 = CEIL8(_L); 
		_S = sizeof_s*8;
		_K_bytes = K/8; 
		_S_bytes = sizeof_s;
		_M_bytes = M/8;
		_Mtag = _M + _S;
		_Mtag_bytes = _M_bytes + _S_bytes;
		_Mtag_bytes_align_16 = _Mtag_bytes + 8;

#ifdef DEBUG_PRINT
		cout << "Constructing ... " << dec << endl;
		cout << "_M    : " << _M 	<< " _M_bytes:    " << _M_bytes << endl;
		cout << "_S    : " << _S 	<< " _S_bytes:    " << _S_bytes << endl;
		cout << "_Mtag : " << _Mtag << " _Mtag_bytes: " << _Mtag_bytes << endl;
		cout << "_Mtag_bytes_align_16: " << _Mtag_bytes_align_16 << endl;
	
		cout << "_L    : " << _L    << " _L_CEIL8:    " << _L_CEIL8 << endl;
		cout << endl << endl;
#endif
		
		_baseOTport = baseOTport;
		_channel = channel;
		_sampling_prg_base = new PrgFromOpenSSLAES (2*L*_K_bytes/16,false,nullptr);
		_sampling_prg = new PrgFromOpenSSLAES (_M*_S_bytes / 16,false,nullptr);
		 auto sk_base =_sampling_prg_base->generateKey(K);
		_sampling_prg_base->setKey(sk_base);
		 auto sk =_sampling_prg->generateKey(K);
		_sampling_prg->setKey(sk);
	}
	 
	protected:
		uint32_t _L;
		uint32_t _L_CEIL8; 
		uint32_t _K;
		uint32_t _K_bytes; 
		uint32_t _S; 
		uint32_t _S_bytes;
		uint32_t _M;
		uint32_t _M_bytes;
		uint32_t _Mtag;
		uint32_t _Mtag_bytes;
		uint32_t _Mtag_bytes_align_16;
		PrgFromOpenSSLAES *_sampling_prg_base;
		PrgFromOpenSSLAES *_sampling_prg;
		shared_ptr<CommParty> _channel;
		int _baseOTport;
		GF2X_Precomputed _gf2x_precomputed;	
};


#endif // COTSHORTKEYS_H___