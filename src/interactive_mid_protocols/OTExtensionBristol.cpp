#ifndef _WIN32
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"



/***********************************/
/*   OTSemiHonestExtensionSender   */
/***********************************/


void OTExtensionBristolBase::init(const string& senderAddress, int port, int my_num, bool isSemiHonest)
{

	int nOTs = 128;

	string hostname, ot_mode, usage;
	int portnum_base = 5000,  nbase = 128;

	OT_ROLE ot_role;

	if (my_num == 0)
		ot_role = SENDER;
	else
		ot_role = RECEIVER;


	vector<string> names(2);

	names[my_num] = "localhost";
	names[1-my_num] = senderAddress;

	pParty.reset(new TwoPartyPlayer(Names(my_num, portnum_base, names), 1 - my_num, 0));

	timeval baseOTstart, baseOTend;
	gettimeofday(&baseOTstart, NULL);
	BaseOT baseOT = BaseOT(nbase, 128, 1 - my_num, pParty.get(), INV_ROLE(ot_role));
	gettimeofday(&baseOTend, NULL);
	double basetime = timeval_diff(&baseOTstart, &baseOTend);
	cout << "\t\tBaseTime (" << role_to_str(ot_role) << "): " << basetime/1000000 << endl << flush;
	cout << "\t\tmeital - BaseTime (" << role_to_str(ot_role) << "): " << (baseOTend.tv_usec - baseOTstart.tv_usec)  << endl;

	baseOT.exec_base();


	BitVector baseReceiverInput(nbase);
	for (int i = 0; i < nbase; i++)
	{
		baseReceiverInput.set_bit(i, baseOT.receiver_inputs[i]);
	}


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

	pOtExt->transfer(nOTs, receiverInput);
	gettimeofday(&transEnd, NULL);
	double transTime = timeval_diff(&transStart, &transEnd);
	cout << "\t\tTransfer (" << "): " << transTime/1000000 << endl << flush;


}

OTExtensionBristolSender::OTExtensionBristolSender(int port,bool isSemiHonest) {

	init("localhost", port, 0, isSemiHonest);
}


shared_ptr<OTBatchSOutput> OTExtensionBristolSender::transfer(OTBatchSInput * input){

	if(input->getType()!= OTBatchSInputTypes::OTExtensionRandomizedSInput){
		throw invalid_argument("input should be instance of OTExtensionRandomizedSInput");
	}
	else{

		//we create a bitvector since the transfer of the bristol library demands that. There is no use of it and thus
		//we do not require that the user inputs that.
		BitVector receiverInput(((OTExtensionRandomizedSInput*)input)->getNumOfOts());
		receiverInput.assign_zero();

		//call the base class transfer that eventually calls the ot extenstion of the bristol library
		OTExtensionBristolBase::transfer(((OTExtensionRandomizedSInput*)input)->getNumOfOts(),receiverInput);

		//return a shared pointer of the output as it taken from the ot object of the library
		//return make_shared<OTExtensionBristolRandomizedSOutput>(pOtExt->senderOutputMatrices);

		auto shared = std::shared_ptr<OTExtensionBristolRandomizedSOutput>(new OTExtensionBristolRandomizedSOutput(pOtExt->senderOutputMatrices));

		return shared;
	}
}


OTExtensionBristolReciever::OTExtensionBristolReciever(const string& senderAddress, int port,bool isSemiHonest) {

	init(senderAddress, port, 1, isSemiHonest);

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
