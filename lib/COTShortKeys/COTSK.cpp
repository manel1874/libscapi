#include "COTSK.h"
#include "COTSK_types.h"
#include "COTSK_impl.h"
#include "MPCCommunicationEX.hpp"
#include "../../include/comm/Comm.hpp"

/*********************************************
    COTSK_pOne::COTSK_pOne
**********************************************/
COTSK_pOne::COTSK_pOne(	uint8_t lBits,
						uint32_t mBits,
 						int partyIdInCommitee,
 						const string & serverAddr,
						const vector<string> &peerIps) :
    _senders(peerIps.size()),
	_nPeers(peerIps.size()),_lBits(lBits), _mBits(mBits), _mtagBits(mBits+8*sizeof(uint64_t))
{
	assert(_nPeers <= 100);
	_peers = MPCEXsetCommunication(_io_service, partyIdInCommitee, serverAddr, true ,peerIps);

	for (int i=0; i < _nPeers; i++) {
		int baseOTport = BASEOT_FIRST_PORT + partyIdInCommitee + 100*i;
		_senders[i] = new COTSK_SenderS64(serverAddr, baseOTport, _peers[i]->getChannel(), _lBits, BASE_K, _mBits);
	}
		
}
/*********************************************
    COTSK_pOne::initialize
**********************************************/
void COTSK_pOne::initialize(const vector<byte> & delta) {

	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_SenderS64::initialize,_senders[i],std::ref(delta));
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}	
}

/*********************************************
    COTSK_pOne::extend
**********************************************/
void COTSK_pOne::extend (vector<byte *> & q_i_j) {

	vector<thread> threads(_nPeers);
 	for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_SenderS64::extend,_senders[i], &(q_i_j[i]));
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}	

}

/*********************************************
    COTSK_pOne::switchCorrelation
**********************************************/
void COTSK_pOne::switchCorrelation(const vector<byte> & delta) {
	//as all allocation in CTOR, this works fine
	//we re-key the OT PRG, sampling PRG can still be reused
	this->initialize(delta);

}

/*********************************************
    COTSK_pOne::close
**********************************************/
void COTSK_pOne::close()
{
	
}
	
COTSK_pOne::~COTSK_pOne()
{
	close();
}

/*********************************************
    COTSK_pTwo::COTSK_pTwo
**********************************************/
COTSK_pTwo::COTSK_pTwo(uint8_t lBits, 
					   uint32_t mBits, 
					   int partyIdInCommitee, 
					   const string & serverAddr,
					   const vector<string> &peerIps): 
	_receivers(peerIps.size()),
	_nPeers(peerIps.size()),_lBits(lBits), _mBits(mBits), _mtagBits(mBits+8*sizeof(uint64_t))

{
	assert(_nPeers <= 100);
	_peers = MPCEXsetCommunication(_io_service, partyIdInCommitee, serverAddr, false ,peerIps);
	
	for (int i=0; i < _nPeers; i++) {
		int baseOTport = BASEOT_FIRST_PORT + 100*partyIdInCommitee + i;
		_receivers[i] = new COTSK_ReceiverS64(baseOTport,_peers[i]->getChannel(),_lBits, BASE_K, _mBits);
	}

}
/*********************************************
    COTSK_pTwo::initialize
**********************************************/
void COTSK_pTwo::initialize() {
	
 	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_ReceiverS64::initialize,_receivers[i]);
 	}
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}
}

/*********************************************
    COTSK_pTwo::extend()
**********************************************/
void COTSK_pTwo::extend(
					const byte *x_h_j, 
					vector<byte *> & t_j_i_out) {
	
	vector<thread> threads(_nPeers);
    for (int i=0; i<_nPeers; i++) {
		threads[i] = thread(&COTSK_ReceiverS64::extend,_receivers[i], &(t_j_i_out[i]) , x_h_j , nullptr);
    }
	for (int i=0; i<_nPeers; i++) {
		  threads[i].join();
	}
}

/*********************************************
    COTSK_pTwo::sitchCorrelation()
**********************************************/
void COTSK_pTwo::switchCorrelation() {
	//as all allocation in CTOR, this works fine
	//sampling PRG can still be reused
	this->initialize();
}


/*********************************************
    COTSK_pTwo::close()
**********************************************/
void COTSK_pTwo::close() {
}
	
COTSK_pTwo::~COTSK_pTwo() {
	close();
}

/*********************************************
    COMM : Moved to here so we have one COTSK.o 
	output
**********************************************/
vector<shared_ptr<ProtocolPartyDataEX> > MPCEXsetCommunication (boost::asio::io_service & io_service, 
                                                               int partyID,
                                                               const string & selfAddr,
                                                               bool isSelfpOne,  
                                                               const vector<string> & peerIps) {
    
    int nPeers = peerIps.size();
    vector<shared_ptr<ProtocolPartyDataEX>> parties(nPeers);
  
    SocketPartyData me, other;
		
 	int role = isSelfpOne ? 0 : 1; //0 server, 1 client
    
    for (int i=0; i<nPeers; i++) {
		
		int port =  isSelfpOne ? (FIRST_PORT + 100*partyID + i) : (FIRST_PORT + partyID + 100*i);
			
        me = SocketPartyData(boost_ip::address::from_string(selfAddr),port);
		
        other = SocketPartyData(boost_ip::address::from_string(peerIps[i]), port);
		
        shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other, role);
		
        cout << " role: "  << role << " peer: " << i << " port: " << port << endl ;
       
		channel->join(500, 5000);
        
		cout << "after join" << endl;
		
        parties[i] = make_shared<ProtocolPartyDataEX>(i, channel);
     }

    return parties;

}
