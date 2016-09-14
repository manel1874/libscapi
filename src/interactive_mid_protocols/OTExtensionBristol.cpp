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
	//cout << "\t\tBaseTime (" << role_to_str(ot_role) << "): " << basetime/1000000 << endl << flush;

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

	//cout<<"nOTs in transfer: "<< nOTs<<endl;


	timeval transStart,transEnd;
	gettimeofday(&transStart, NULL);
	//call the transfer using the OT extension object of the underlying library.
	pOtExt->transfer(nOTs, receiverInput);
	gettimeofday(&transEnd, NULL);
	double transTime = timeval_diff(&transStart, &transEnd);
	//cout << "\t\tTransfer (" << "): " << transTime/1000000 << endl << flush;


}

OTExtensionBristolSender::OTExtensionBristolSender(int port,bool isSemiHonest, shared_ptr<CommParty> channel) {

	//Call the init of the base class. The host name is hard coded to localhost since the sender is the  listener.
	init("localhost", port, 0, isSemiHonest, channel);
}


shared_ptr<OTBatchSOutput> OTExtensionBristolSender::transfer(OTBatchSInput * input){


	if(input->getType()!= OTBatchSInputTypes::OTExtensionRandomizedSInput && input->getType()!= OTBatchSInputTypes::OTExtensionGeneralSInput){
		throw invalid_argument("input should be instance of OTExtensionRandomizedSInput or OTExtensionGeneralSInput.");
	}
	else{
		int nOTs;

		if(input->getType()== OTBatchSInputTypes::OTExtensionGeneralSInput){

			nOTs = ((OTExtensionGeneralSInput *)input)->getNumOfOts();
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

		if(input->getType()== OTBatchSInputTypes::OTExtensionGeneralSInput){//need another round of communication using the channel member

			if (channel == NULL) {
					throw runtime_error("In order to execute a general ot extension the channel must be given");
			}

			auto x0Vec = ((OTExtensionGeneralSInput *)input)->getX0Arr();
			auto x1Vec = ((OTExtensionGeneralSInput *)input)->getX1Arr();

			__m128i* x0 = (__m128i*)x0Vec.data();
			__m128i* x1 = (__m128i*)x1Vec.data();
			for(int i=0; i<nOTs; i++){

					x0[i] =  x0[i]^ pOtExt->senderOutputMatrices[0].squares[i/128].rows[i % 128];
					x1[i] =  x1[i]^ pOtExt->senderOutputMatrices[1].squares[i/128].rows[i % 128];
			}

			//send the bitmatrix over the channel. The underlying array of the vector of squares can be viewed as one long array of bytes.
			channel->write((byte *)x0, (((OTExtensionGeneralSInput *)input)->getX0Arr()).size());
			channel->write((byte *)x1, (((OTExtensionGeneralSInput *)input)->getX1Arr()).size());

			return nullptr;

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


	if (input->getType() != OTBatchRInputTypes::OTExtensionGeneralRInput && input->getType() != OTBatchRInputTypes::OTExtensionRandomizedRInput){
		throw invalid_argument("input should be instance of OTExtensionGeneralRInput or OTExtensionRandomizedRInput.");
	}
	else{

		auto sigmaArr = ((OTExtensionRInput *)input)->getSigmaArr();

		auto nOTs = sigmaArr.size();


		BitVector inputBits(nOTs);

		inputBits.assign_zero();

		//fill the bit vector that bristol needs from the sigma array

		for(int i=0; i<nOTs; i++){

			if(sigmaArr[i]==1)
				inputBits.set_bit(i,1);
		}

		OTExtensionBristolBase::transfer(nOTs,inputBits);

		//we need to get the xor of the randomized and real data from the sender.
		if(input->getType() == OTBatchRInputTypes::OTExtensionGeneralRInput){

			if (channel == NULL) {
				throw runtime_error("In order to execute a general ot extension the channel must be given");
			}


			//cout<<"in transfer general"<<endl;
			auto sizeInBytes = nOTs*16;
			__m128i* x0Arr = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);
			__m128i* x1Arr = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);

			channel->read((byte *)x0Arr, sizeInBytes);
			channel->read((byte *)x1Arr, sizeInBytes);

			__m128i* outputSigma = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);

			//create alligned arrays


			//memcpy ( x0Arr, bufferx0, sizeInBytes );
			//memcpy ( x1Arr, bufferx1, sizeInBytes );

			//cout<<"x0Arr[0] = "<<(((int*)x0Arr)[0])<<endl;
			//cout<<"x1Arr[0] = "<<(((int*)x1Arr)[0])<<endl;


			//xor each randomized output with the relevant xored sent from the sender
			for(int i=0; i<nOTs; i++){
				if(inputBits.get_bit(i)==0)
					outputSigma[i] =  x0Arr[i]^ pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
				else
					outputSigma[i] =  x1Arr[i]^ pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
			}

			vector<byte> output;

			copy_byte_array_to_byte_vector((byte*)outputSigma, nOTs, output, 0);

			 _mm_free(x0Arr);
			 _mm_free(x1Arr);
			 _mm_free(outputSigma);

			return make_shared<OTOnByteArrayROutput>(output);

		}
		else{

			vector<byte> output;

			copy_byte_array_to_byte_vector((byte*)(pOtExt->receiverOutputMatrix.squares.data()), nOTs*16, output, 0);


			return make_shared<OTOnByteArrayROutput>(output);
		}


	}

}
#endif
