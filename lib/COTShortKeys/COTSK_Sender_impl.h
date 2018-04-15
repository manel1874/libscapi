#ifndef COTSHORTKEYS_SENDER_IMPL_H___
#define COTSHORTKEYS_SENDER_IMPL_H___

#include "COTSK_impl.h"
/*
    HELPER METHODS   
*/
/*********************************************
    CLASS DEFINITION - SENDER
**********************************************/
template<class S> 
class COTSK_Sender : public COTSK_Base {
	public:
		COTSK_Sender(const string& serverAddr, 
					 int baseOTport, 
					 const shared_ptr<CommParty> & channel,
					 uint32_t L,
					 uint32_t K,
					 uint32_t M);	

		void initialize(const vector<byte> & delta); //delta has l bytes, each byte is 0 or 1
	
		void extend(byte **q_j_out); //qj_out: array of (m_tag_bits * L) bits
	
	private:
		vector<byte> _delta;
		vector<PrgFromOpenSSLAES *> _prg_delta;
		const string& _serverAddr;
		byte* _prg_delta_buff;
		byte* _q_j_out; 
		byte *_qi;
		byte *_u;
		byte *_chi;
	
};

/*********************************************
    SENDER CTOR
**********************************************/
template <class S>
COTSK_Sender<S>::COTSK_Sender( const string& serverAddr, 
                            int baseOTport, 
                            const shared_ptr<CommParty> & channel, 
                            uint32_t L, 
                            uint32_t K, 
                            uint32_t M) : COTSK_Base(baseOTport,channel,L,K,M,sizeof(S)),_serverAddr(serverAddr)
{
	_Mtag_bytes_align_16 = (M+sizeof(S)*8+64)/8;
	this->_prg_delta_buff = (byte *) _mm_malloc(_L_CEIL8*_Mtag_bytes_align_16,16); 
	this->_q_j_out =  (byte *) _mm_malloc(_L_CEIL8*_Mtag_bytes_align_16,16);
	this->_qi = (byte *) _mm_malloc (_L_CEIL8*_Mtag_bytes_align_16, 16); 
	this->_u = (byte *) _mm_malloc (_L*_Mtag_bytes_align_16, 16); 
    //this->_chi = (byte *) _mm_malloc (_M*_S_bytes,16);
 
	
	this->_prg_delta.resize(L);
	for (uint32_t i = 0; i < L; i++) {
		this->_prg_delta[i] = new PrgFromOpenSSLAES(_Mtag_bytes_align_16 / 16, false, _prg_delta_buff+i*_Mtag_bytes_align_16);
	}
}

/*********************************************
    SENDER INITIALIZE 
**********************************************/
template <class S>
void COTSK_Sender<S>::initialize(const vector<byte> & delta)
{
	_delta = delta;
	assert (delta.size() == _L);
#ifdef DEBUG_PRINT
	cout << "delta: " ;
	for (uint32_t i=0; i < delta.size(); i++) {
		cout << hex << (int)delta[i] << " ";
	}
	cout << endl;
#endif
	
#ifdef DEBUG_PRINT
	cout << "Initializing OTBristolReceiver...." << endl;
#endif	
	
  	OTExtensionBristolReceiver receiver(_serverAddr,this->_baseOTport,true,this->_channel);
 
#ifdef DEBUG_PRINT
	cout << "OTBristolReceiver initialized" << endl;
#endif	
	
	_delta.insert( _delta.begin(), 0);
    OTBatchRInput * input = new OTExtensionGeneralRInput(_delta, _K);
 	
	auto start = scapi_now();
#ifdef DEBUG_PRINT
	cout << "Calling OT transfer...." << endl;
#endif	
    auto output = receiver.transfer(input);
    print_elapsed_ms(start, "Base Transfer");

	auto out = (OTOnByteArrayROutput *) output.get();
#ifdef DEBUG_PRINT
	cout << "First byte of each selected key: " << endl ;
#endif	
 	for (uint32_t i= 0; i < _L; i++) {
		byte *b = out->getXSigma().data() + (i+1)*_K_bytes;
#ifdef DEBUG_PRINT
		cout <<  hex << (int)b[0] << " " ;
#endif		
		SecretKey sk( b, _K_bytes ,"AES128");
		_prg_delta[i]->setKey(sk);
	}
#ifdef DEBUG_PRINT
		cout <<  endl; 
#endif	
}	

/*********************************************
    SENDER EXTEND 
**********************************************/
template <class S>
void COTSK_Sender<S>::extend(byte **q_j_out)
{
	byte *t_i_delta;
	(*q_j_out) = _q_j_out;
	this->_channel->read(_u, _L*_Mtag_bytes_align_16);

#ifdef DEBUG_PRINT
        cout << "** Sender extend :: read u, size= " << dec << _L*_Mtag_bytes_align_16 << endl;
#endif	
	
    for (uint32_t i = 0; i < _L; i++) {
		t_i_delta = this->_prg_delta[i]->getPRGBytesEX(_Mtag_bytes_align_16);
		for (uint32_t j=0;j<_Mtag_bytes;j++) {
			if (_delta[i]) {
				_qi[i*_Mtag_bytes_align_16+j] =  _u[i*_Mtag_bytes_align_16+j] ^ t_i_delta[j];
			}
			else {
				_qi[i*_Mtag_bytes_align_16+j] = t_i_delta[j];
			}
				
		}
	}	

	if (_L == 1)
		return;

#ifdef DEBUG_PRINT
    cout << "** Sender extend :: Entering transpose " << endl;
#endif		
	transpose(_L_CEIL8,_qi,_Mtag_bytes_align_16,_q_j_out);	
#ifdef DEBUG_PRINT
    cout << "** Sender extend :: transpose " << endl;
#endif	
	
	//check consistency
  
	_chi = this->_sampling_prg->getPRGBytesEX(_M*_S_bytes);
#ifdef DEBUG_PRINT
    cout << "** Sender check correlation: sampled m=  " << dec << _M << " _S_bytes " << _S_bytes << endl;
#endif	
	
   	this->_channel->write(_chi,_M*_S_bytes);
	
#ifdef DEBUG_PRINT
    cout << "** Sender check correlation: sent chi  " << dec << _M*_S_bytes << " bytes " << endl;
#endif	
 
	S y,tau,nu=0;
	
	this->_channel->read((byte *)&y,sizeof(S));

#ifdef DEBUG_PRINT
        cout << "** Sender : recieved y = " << dec << y << endl;
#endif	
	
 	this->_channel->read((byte *)&tau,sizeof(S));

#ifdef DEBUG_PRINT
        cout << "** Sender : recieved tau = " << dec << tau << endl;
#endif	
		
	S *p_chi = (S *)_chi;
    for (uint32_t j=0; j < _M; j++) {
    	if (index(_q_j_out,j)) {
			nu = nu ^ p_chi[j];
		}
	}
	for (uint32_t j=0; j < _S; j++) {
    	if (index(_q_j_out,j+_M)) {
			nu = nu ^ _gf2x_precomputed.get(j);
		}
	}

}

#endif // COTSHORTKEYS_H___