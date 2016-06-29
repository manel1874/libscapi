#pragma once

#include "../CryptoInfra/SecurityLevel.hpp"
#include <OTExtensionBristol/OT/OTExtensionWithMatrix.h>
#include "OTBatch.hpp"
#include <memory>

using namespace std;


class OTExtensionBristolBase : public Malicious{

protected:

	unique_ptr<OTExtensionWithMatrix> pOtExt;
	unique_ptr<TwoPartyPlayer> pParty;

public:


	void transfer(int nOTs, const BitVector& receiverInput);
protected:


	void init(const char* address, int port, int my_num, bool isSemiHonest);
};

class OTExtensionBristolReciever: public OTExtensionBristolBase,  public OTBatchReceiver{

public:
	OTExtensionBristolReciever(const char* address, int port, bool isSemiHonest);
	/*void transfer(int nOTs, const BitVector& receiverInput){ cout << "in transfer reciever" <<endl;
															OTExtensionBristolBase::transfer(nOTs,receiverInput);}
*/
	shared_ptr<OTBatchROutput> transfer(OTBatchRInput * input);

};


class OTExtensionBristolSender: public OTExtensionBristolBase/*, public OTBatchSender*/{

public:
	OTExtensionBristolSender(const char* address, int port, bool isSemiHonest);
	void transfer(int nOTs){cout << "in transfer sender" <<endl;
                            BitVector receiverInput(nOTs);
                            OTExtensionBristolBase::transfer(nOTs,receiverInput);   };




};
