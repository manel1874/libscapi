#ifndef _WIN32
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"



/***********************************/
/*   OTSemiHonestExtensionSender   */
/***********************************/





void OTExtensionScapi::init(const char* address, int port, int my_num)
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
	names[1-my_num] = "localhost";

	pParty.reset(new TwoPartyPlayer(Names(my_num, portnum_base, names), 1 - my_num, 7000));

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
									   true));


}




void OTExtensionScapi::transfer(int nOTs, const BitVector& receiverInput2) {

	cout<<"nOTs in transfer: "<< nOTs<<endl;


	timeval transStart,transEnd;
	gettimeofday(&transStart, NULL);
	if(pOtExt== nullptr){
		cout<<"I am null"<<endl;
	}
	pOtExt->transfer(nOTs, receiverInput2);
	gettimeofday(&transEnd, NULL);
	double transTime = timeval_diff(&transStart, &transEnd);
	cout << "\t\tTransfer (" << "): " << transTime/1000000 << endl << flush;


}

OTSemiHonestExtensionSender::OTSemiHonestExtensionSender(const char* address, int port) {

	init(address, port, 0);
}


OTSemiHonestExtensionReciever::OTSemiHonestExtensionReciever(const char* address, int port) {

	init(address, port, 1);

}
#endif