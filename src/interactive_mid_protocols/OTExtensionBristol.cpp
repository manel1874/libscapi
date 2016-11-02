#ifndef _WIN32
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"


void OTExtensionBristolBase::init(const string& senderAddress, int port, int my_num, bool isSemiHonest, const shared_ptr<CommParty> & channel)
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

OTExtensionBristolSender::OTExtensionBristolSender(int port,bool isSemiHonest, const shared_ptr<CommParty> & channel) {

	//Call the init of the base class. The host name is hard coded to localhost since the sender is the  listener.
	init("localhost", port, 0, isSemiHonest, channel);
}


shared_ptr<OTBatchSOutput> OTExtensionBristolSender::transfer(OTBatchSInput * input){



	if(input->getType()!= OTBatchSInputTypes::OTExtensionRandomizedSInput &&
	   input->getType()!= OTBatchSInputTypes::OTExtensionGeneralSInput &&
	   input->getType()!= OTBatchSInputTypes::OTExtensionCorrelatedSInput){
		throw invalid_argument("input should be instance of OTExtensionRandomizedSInput or OTExtensionGeneralSInput or OTExtensionCorrelatedSInput.");
	}
	else{
		int nOTs, nOTsReal;



		if(input->getType()== OTBatchSInputTypes::OTExtensionGeneralSInput){

			nOTsReal = ((OTExtensionGeneralSInput *)input)->getNumOfOts();
		}
		else if (input->getType()== OTBatchSInputTypes::OTExtensionRandomizedSInput){
			nOTsReal = (((OTExtensionRandomizedSInput*)input)->getNumOfOts());
		}
		else{
			nOTsReal = (((OTExtensionCorrelatedSInput*)input)->getNumOfOts());
		}

		//round to the nearest 128 multiplication
		nOTs = ((nOTsReal + 128 - 1) / 128) * 128;



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
		else if (input->getType()== OTBatchSInputTypes::OTExtensionCorrelatedSInput){

			if (channel == NULL) {
				throw runtime_error("In order to execute a correlated ot extension the channel must be given");
			}

			auto deltaVec = ((OTExtensionCorrelatedSInput *)input)->getDeltaArr();


			//resize to 128 multiplications
			deltaVec.resize(nOTs*16);


			__m128i* delta = (__m128i*)deltaVec.data();



			__m128i* x1Arr = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);

			//send to the receiver R1^R0^delta
			for(int i=0; i<nOTs; i++){


				x1Arr[i] = delta[i]^ pOtExt->senderOutputMatrices[0].squares[i/128].rows[i % 128];

				//we use delta in order not to create an additional array
				delta[i] =  x1Arr[i] ^ pOtExt->senderOutputMatrices[1].squares[i/128].rows[i % 128];
			}

			//send the vector of R1^R0^delta over the channel.
			channel->write((byte *)delta, nOTs*16);


			vector<byte> x1Output;

			copy_byte_array_to_byte_vector((byte*)x1Arr, nOTsReal*16, x1Output, 0);

			vector<byte> x0Output;

			copy_byte_array_to_byte_vector((byte*)(pOtExt->senderOutputMatrices[0].squares.data()), nOTsReal*16, x0Output, 0);

			_mm_free(x1Arr);

			//the output for the sender is r0 and r0^delta
			return make_shared<OTExtensionCorrelatedSOutput>(x0Output, x1Output);

		}

		else{
			//return a shared pointer of the output as it taken from the ot object of the library
			return make_shared<OTExtensionBristolRandomizedSOutput>(pOtExt->senderOutputMatrices);
		}

	}
}


OTExtensionBristolReceiver::OTExtensionBristolReceiver(const string& senderAddress, int port,bool isSemiHonest, const shared_ptr<CommParty> & channel) {

	init(senderAddress, port, 1, isSemiHonest, channel);

}


shared_ptr<OTBatchROutput> OTExtensionBristolReceiver::transfer(OTBatchRInput * input){


	if (input->getType() != OTBatchRInputTypes::OTExtensionGeneralRInput &&
		input->getType() != OTBatchRInputTypes::OTExtensionRandomizedRInput &&
		input->getType() != OTBatchRInputTypes::OTExtensionCorrelatedRInput){
		throw invalid_argument("input should be instance of OTExtensionGeneralRInput or OTExtensionRandomizedRInput or OTExtensionCorrelatedRInput.");
	}
	else{

		auto sigmaArr = ((OTExtensionRInput *)input)->getSigmaArr();

		auto nOTsReal = sigmaArr.size();

		auto nOTs = ((nOTsReal + 128 - 1) / 128) * 128;

		//make the number of ot's to be a multiplication of 128

		BitVector inputBits(nOTs);

		inputBits.assign_zero();

		//fill the bit vector that bristol needs from the sigma array

		for(size_t i=0; i<nOTsReal; i++){

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
			for(size_t i=0; i<nOTs; i++){
				if(inputBits.get_bit(i)==0)
					outputSigma[i] =  x0Arr[i]^ pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
				else
					outputSigma[i] =  x1Arr[i]^ pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
			}

			vector<byte> output;

			copy_byte_array_to_byte_vector((byte*)outputSigma, nOTsReal*16, output, 0);

			 _mm_free(x0Arr);
			 _mm_free(x1Arr);
			 _mm_free(outputSigma);

			return make_shared<OTOnByteArrayROutput>(output);

		}

		//we need to get the xor of the randomized and real data from the sender.
		else if(input->getType() == OTBatchRInputTypes::OTExtensionCorrelatedRInput){

			if (channel == NULL) {
				throw runtime_error("In order to execute a correlated ot extension the channel must be given");
			}


			//cout<<"in transfer general"<<endl;
			auto sizeInBytes = nOTs*16;
			__m128i* adjustArr = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);

			channel->read((byte *)adjustArr, sizeInBytes);

			__m128i* outputSigma = (__m128i *) _mm_malloc(sizeof(__m128i) * nOTs, 16);

			//create alligned arrays


			//memcpy ( x0Arr, bufferx0, sizeInBytes );
			//memcpy ( x1Arr, bufferx1, sizeInBytes );

			//cout<<"x0Arr[0] = "<<(((int*)x0Arr)[0])<<endl;
			//cout<<"x1Arr[0] = "<<(((int*)x1Arr)[0])<<endl;


			//xor each randomized output with the relevant xored sent from the sender
			for(size_t i=0; i<nOTs; i++){
				if(inputBits.get_bit(i)==0)
					//if the bit is 0 stay with r0 as the randomized ot generated
					outputSigma[i] = pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
				else
					//x1 = adjustArr^r1 = r1^ r0^delta^r1 = ro^delta=x1
					outputSigma[i] =  adjustArr[i]^ pOtExt->receiverOutputMatrix.squares[i/128].rows[i % 128];
			}

			vector<byte> output;

			copy_byte_array_to_byte_vector((byte*)outputSigma, nOTsReal*16, output, 0);

			 _mm_free(adjustArr);
			 _mm_free(outputSigma);

			return make_shared<OTOnByteArrayROutput>(output);

		}


		else{

			vector<byte> output;

			copy_byte_array_to_byte_vector((byte*)(pOtExt->receiverOutputMatrix.squares.data()), nOTsReal*16, output, 0);


			return make_shared<OTOnByteArrayROutput>(output);
		}


	}

}
#endif
