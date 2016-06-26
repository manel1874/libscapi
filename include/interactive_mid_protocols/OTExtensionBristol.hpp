#pragma once

#include <OTExtensionBristol/OT/OTExtensionWithMatrix.h>
#include <memory>

using namespace std;


class OTExtensionScapi{

protected:

	unique_ptr<OTExtensionWithMatrix> pOtExt;
	unique_ptr<TwoPartyPlayer> pParty;

public:


	void transfer(int nOTs, const BitVector& receiverInput);
protected:


	void init(const char* address, int port, int my_num);
};

class OTSemiHonestExtensionReciever: public OTExtensionScapi{

public:
	OTSemiHonestExtensionReciever(const char* address, int port);
	void transfer(int nOTs, const BitVector& receiverInput){ cout << "in transfer reciever" <<endl;
                                                    OTExtensionScapi::transfer(nOTs,receiverInput);}


};


class OTSemiHonestExtensionSender: public OTExtensionScapi{

public:
	OTSemiHonestExtensionSender(const char* address, int port);
	void transfer(int nOTs){cout << "in transfer sender" <<endl;
                            BitVector receiverInput(nOTs);
                            OTExtensionScapi::transfer(nOTs,receiverInput);   };


};
