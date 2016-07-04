#ifndef _WIN32
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"


void OTExtensionBristolBase::init(const string& senderAddress, int port, int my_num, bool isSemiHonest, shared_ptr<CommParty> channel)
{

	this->channel = channel;

	OT_ROLE ot_role;

	if (my_num == 0)
		ot_role = SENDER;
	else
		ot_role = RECEIVER;


	//Set the host names. The sender is the listener.
	vector<string> names(2);
	names[my_num] = "localhost";
	names[1-my_num] = senderAddress;

	pParty.reset(new TwoPartyPlayer(Names(my_num, 0, names), 1 - my_num, port));

	timeval baseOTstart, baseOTend;
	gettimeofday(&baseOTstart, NULL);
	//init the base OT with 128 ot's with 128 bit length for the relevant role.
	BaseOT baseOT = BaseOT(128, 128, 1 - my_num, pParty.get(), INV_ROLE(ot_role));
	gettimeofday(&baseOTend, NULL);
	double basetime = timeval_diff(&baseOTstart, &baseOTend);
	cout << "\t\tBaseTime (" << role_to_str(ot_role) << "): " << basetime/1000000 << endl << flush;

	//run the base OT
	baseOT.exec_base();


	BitVector baseReceiverInput(128);
	for (int i = 0; i < 128; i++)
	{
		baseReceiverInput.set_bit(i, baseOT.receiver_inputs[i]);
	}


	//set the unique pointer to t he ot extension object.
	pOtExt.reset(new OTExtensionWithMatrix(128, baseOT.length(),
									   1, 1,
									   pParty.get(),
									   baseReceiverInput,
									   baseOT.sender_inputs,
									   baseOT.receiver_outputs,
									   ot_role,
									   isSemiHonest));


}




void OTExtensionBristolBase::transfer(int nOTs, const BitVector& receiverInput) {

	cout<<"nOTs in transfer: "<< nOTs<<endl;


	timeval transStart,transEnd;
	gettimeofday(&transStart, NULL);
	//call the transfer using the OT extension object of the underlying library.
	pOtExt->transfer(nOTs, receiverInput);
	gettimeofday(&transEnd, NULL);
	double transTime = timeval_diff(&transStart, &transEnd);
	cout << "\t\tTransfer (" << "): " << transTime/1000000 << endl << flush;


}

OTExtensionBristolSender::OTExtensionBristolSender(int port,bool isSemiHonest, shared_ptr<CommParty> channel) {

	//Call the init of the base class. The host name is hard coded to localhost since the sender is the  listener.
	init("localhost", port, 0, isSemiHonest, channel);
}


shared_ptr<OTBatchSOutput> OTExtensionBristolSender::transfer(OTBatchSInput * input){

	if(input->getType()!= OTBatchSInputTypes::OTExtensionRandomizedSInput || input->getType()!= OTBatchSInputTypes::OTExtensionGeneralSInput){
		throw invalid_argument("input should be instance of OTExtensionRandomizedSInput");
	}
	else{
		int nOTs;

		if(input->getType()!= OTBatchSInputTypes::OTExtensionGeneralBristolSInput){

			nOTs = (((OTExtensionGeneralSInput*)input)->getNumOfOts());
		}
		else{
			nOTs = (((OTExtensionRandomizedSInput*)input)->getNumOfOts());
		}


		//we create a bitvector since the transfer of the bristol library demands that. There is no use of it and thus
		//we do not require that the user inputs that.
		BitVector receiverInput(nOTs);
//		receiverInput.assign_zero();

		//call the base class transfer that eventually calls the ot extenstion of the bristol library
		OTExtensionBristolBase::transfer(nOTs,receiverInput);

		if(input->getType()!= OTBatchSInputTypes::OTExtensionGeneralBristolSInput){//need another round of communication using the channel member

			//xor every input with the randomized output
			((OTExtensionGeneralBristolSInput *)input)->x0Arr ^=   pOtExt->senderOutputMatrices[0];
			((OTExtensionGeneralBristolSInput *)input)->x1Arr ^=   pOtExt->senderOutputMatrices[1];

		}

		else{
			//return a shared pointer of the output as it taken from the ot object of the library
			return make_shared<OTExtensionBristolRandomizedSOutput>(pOtExt->senderOutputMatrices);
		}

	}
}


OTExtensionBristolReciever::OTExtensionBristolReciever(const string& senderAddress, int port,bool isSemiHonest, shared_ptr<CommParty> channel) {

	init(senderAddress, port, 1, isSemiHonest, channel);

}


shared_ptr<OTBatchROutput> OTExtensionBristolReciever::transfer(OTBatchRInput * input){

	if (input->getType() != OTBatchRInputTypes::OTExtensionBristolRInput){
		throw invalid_argument("input should be instance of OTExtensionBristolRInput");
	}
	else{
		((OTExtensionBristolRInput *)input)->receiverInput;

		OTExtensionBristolBase::transfer(((OTExtensionBristolRInput *)input)->nOTs,((OTExtensionBristolRInput *)input)->receiverInput);

		return make_shared<OTExtensionBristolROutput>(pOtExt->receiverOutputMatrix);
	}

}
#endif
