#ifndef COTSHORTKEYS_RECEIVER_IMPL_H___
#define COTSHORTKEYS_RECEIVER_IMPL_H___

#include "COTSK_impl.h"

/*********************************************
    CLASS DEFINITION - COTSK_RECEIVER
**********************************************/
template<class S>
class COTSK_Receiver : public COTSK_Base {
	public:
	
		COTSK_Receiver(int baseOTport,
					   const shared_ptr<CommParty> & channel ,
					   uint32_t L,
					   uint32_t K,
					   uint32_t M);
	
		void initialize();
	
		void extend(byte **t_j_i_out, 
					const byte *x,			
					const byte *r = nullptr);  // if nullptr passed, the callee will sample random 
			
	private:
		vector<PrgFromOpenSSLAES *> _prg0;
		vector<PrgFromOpenSSLAES *> _prg1;
		byte *_prg0_buff;
		byte *_prg1_buff;
		byte *_tj0_out;
		byte *_u;
		byte *_chi;
};

/*********************************************
    RECEIVER CTOR
**********************************************/
template <class S>
COTSK_Receiver<S>::COTSK_Receiver(	int baseOTport, 
                 	              	const shared_ptr<CommParty> & channel,
                    	           	uint32_t L,
                        	       	uint32_t K,
                            	   	uint32_t M) : COTSK_Base(baseOTport,channel,L,K,M,sizeof(S))
{	
	_Mtag_bytes_align_16 = (M+sizeof(S)*8+64)/8;
	this->_tj0_out =   (byte *) _mm_malloc(_L_CEIL8*_Mtag_bytes_align_16,16);
	this->_prg0_buff = (byte *) _mm_malloc(_L_CEIL8*_Mtag_bytes_align_16,16); 
	this->_prg1_buff = (byte *) _mm_malloc(_L_CEIL8*_Mtag_bytes_align_16,16); 
	this->_u = (byte *) _mm_malloc(_L*_Mtag_bytes_align_16,16);
    this->_chi = (byte *) _mm_malloc (_M*_S_bytes,16);

	this->_prg0.resize(L);
	this->_prg1.resize(L);	
	for (uint32_t i = 0; i < L; i++) {
		this->_prg0[i] = new PrgFromOpenSSLAES(_Mtag_bytes_align_16 / 16,false,_prg0_buff+i*_Mtag_bytes_align_16);
		this->_prg1[i] = new PrgFromOpenSSLAES(_Mtag_bytes_align_16 / 16,false,_prg1_buff+i*_Mtag_bytes_align_16);
		
	}
}

/*********************************************
    RECEIVER INITIALIZE
**********************************************/

template <class S>
void COTSK_Receiver<S>::initialize()
{
#ifdef DEBUG_PRINT
	cout << "Initializing OTBristolSender...." << endl;
#endif	
	
  	OTExtensionBristolSender sender(this->_baseOTport,true,this->_channel);
#ifdef DEBUG_PRINT
	cout << "OTBristolSender initialized" << endl;
#endif	
	//bug workaround: OT extension returns bad value for first OT, so we use 1 more.
	vector<byte> x0Arr((_L+1)*_K_bytes) ; 
	vector<byte> x1Arr((_L+1)*_K_bytes) ; 

#ifdef DEBUG_PRINT
	cout << "Sampling Prg..." << endl;
#endif	
	
	this->_sampling_prg_base->getPRGBytes(x0Arr,0,x0Arr.size());
	this->_sampling_prg_base->getPRGBytes(x1Arr,0,x1Arr.size());
	
	OTBatchSInput *input = new OTExtensionGeneralSInput(x0Arr, x1Arr, _L+1);
		
   	auto start = scapi_now();
#ifdef DEBUG_PRINT
	cout << "Calling OT transfer...." << endl;
#endif	
 	
   	auto output = sender.transfer(input);
   	print_elapsed_ms(start, "Base Transfer");
 	
	for (uint32_t i= 0; i < _L; i++) {
		SecretKey sk0(x0Arr.data() + (i+1)*_K_bytes , _K_bytes ,"AES128");
		SecretKey sk1(x1Arr.data() + (i+1)*_K_bytes , _K_bytes ,"AES128");
		this->_prg0[i]->setKey(sk0);
		this->_prg1[i]->setKey(sk1);
	}
	
#ifdef DEBUG_PRINT
	cout << "Arr 0 : First byte of each key" << endl; 
	for (uint32_t i= 0; i < _L; i++) {
		cout << hex << (int)(x0Arr.data() + (i+1)*_K_bytes)[0] << " ";		
	}	
	cout << endl;
	
	cout << "Arr 1 : First byte of each key" << endl; 
	for (uint32_t i= 0; i < _L; i++) {
		cout << hex << (int)(x1Arr.data() + (i+1)*_K_bytes)[0] << " ";		
	}	
	cout << endl;
	
#endif
}

/*********************************************
    RECEIVER EXTEND 
**********************************************/
template <class S>
void COTSK_Receiver<S>::extend(byte **t_j_i_out ,const byte *x, const byte *r) {

#ifdef DEBUG_PRINT
	cout << dec << " LCEIL " << _L_CEIL8 << " _Mtag_bytes_align_16 " <<_Mtag_bytes_align_16 << endl;
 	auto start = scapi_now();
#endif
	
	const byte * r_j_i_k = (r != nullptr) ? r : _sampling_prg->getPRGBytesEX(_M*_S_bytes);

#ifdef DEBUG_PRINT
	cout << " Receiver Extend: sampled random data" << endl;
 	start = scapi_now();
#endif
	
	(*t_j_i_out) = _tj0_out; //always return pointer to internal buffer 
	byte *ti0_0 = nullptr;
	//byte *ti1_0 = nullptr;
	
	byte *ti0;
	byte *ti1;

#ifdef DEBUG_PRINT
	cout << " Receiver Extend: Fixed Pointers" << endl;
 	start = scapi_now();
#endif	
	for (uint32_t i = 0; i < _L; i++) {
		ti0 = this->_prg0[i]->getPRGBytesEX(_Mtag_bytes_align_16);
		ti1 = this->_prg1[i]->getPRGBytesEX(_Mtag_bytes_align_16);
	
		uint32_t row_offset = i*_Mtag_bytes_align_16;
	//	cout << "ROW OFFSET " << row_offset << endl;
		
		for (uint32_t j=0;j<_M_bytes;j++) {
			_u[row_offset+j] = (ti0[j] ^ ti1[j]) ^ x[j];
		}
		
	//	cout << "DONE LOOP ONE " << endl;
		for (uint32_t j=0;j<_S_bytes ;j++) {
			_u[row_offset+(_M_bytes+j)] = (ti0[_M_bytes+j] ^ ti1[_M_bytes+j]) ^ r_j_i_k[i*_S_bytes + j];
		}

	//	cout << "DONE LOOP TWO " << endl;
			
		if (i == 0) {
			ti0_0 = ti0;
			//ti1_0 = ti1;
		}
	}
#ifdef DEBUG_PRINT
        cout << "** Receiver extend :: extended into t0, t1" << endl;
#endif	
	
	this->_channel->write(_u,_L*_Mtag_bytes_align_16);

#ifdef DEBUG_PRINT
        cout << "** Receiver extend: sent u: bytes= "  << _L*_Mtag_bytes_align_16 << endl;
#endif	
	if (_L == 1)
		return;
	
	transpose(_L_CEIL8,ti0_0,_Mtag_bytes_align_16,_tj0_out);	
#ifdef DEBUG_PRINT
    cout << "** Receiver extend :: transpose" << endl;
#endif	

	//check consistency
  	this->_channel->read(_chi,_M*_S_bytes);

#ifdef DEBUG_PRINT
        cout << "** Receiver : reading chi bytes= 1 " << dec <<_M*_S_bytes << endl;
#endif	
	
	S y=0,tau=0; 

	S *p_chi = (S *)_chi;
	
    for (uint32_t j=0; j < _M; j++) {
    	if (index(x,j)) {
			y = y ^ p_chi[j];
		}
   		if (index(_tj0_out,j)) { 
			tau = tau ^ p_chi[j];
		}
    }
	
	for (uint32_t j=0; j < _S; j++) {
    	if (index(r_j_i_k,j)) {
			y = y ^ this->_gf2x_precomputed.get(j);
		}
   		if (index(_tj0_out,_M+j)) { 
			tau = tau ^ this->_gf2x_precomputed.get(j);
		}
    }

 	this->_channel->write((byte *)&y,sizeof(S));
	
#ifdef DEBUG_PRINT
        cout << "** Receiver : sending y = " << dec << y << endl;
#endif	
	
 	_channel->write((byte *)&tau,sizeof(S));
#ifdef DEBUG_PRINT
     cout << "** Receiver : sending tau = " << dec << tau << endl;
#endif	
	
#ifdef DEBUG_PRINT
	print_elapsed_ms(start, "Extend ");	
#endif
}

#endif // COTSHORTKEYS_H___