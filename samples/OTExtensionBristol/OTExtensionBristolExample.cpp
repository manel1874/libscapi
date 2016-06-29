#ifndef _WIN32
#include <iostream>
#include "../../include/interactive_mid_protocols/OTExtensionBristol.hpp"

using namespace std;

int mainBristol(string partyNum) {

    int my_num = stoi(partyNum);


    int nOTs = 1280000;


    BitVector receiverInput(nOTs);
    receiverInput.assign_zero();

    receiverInput.set_bit(0,1);


    if (my_num == 0) {
        cout<<"nOTS: "<< nOTs<<endl;
        OTExtensionBristolSender sender(12000,false);

        auto input = new OTExtensionRandomizedSInput(nOTs);
        auto output = sender.transfer(input);

        ((OTExtensionBristolRandomizedSOutput*)output.get())->senderOutputMatrices[0].print_side_by_side(((OTExtensionBristolRandomizedSOutput*)output.get())->senderOutputMatrices[1]);


    }
    else {
        cout<<"nOTS: "<< nOTs<<endl;
        OTExtensionBristolReciever reciever("localhost", 12000,false);

        OTBatchRInput * input = new OTExtensionBristolRInput(nOTs, receiverInput);


        auto output = reciever.transfer(input);

        for (int i = 0; i < 32; i++){
			for (int j = 0; j < 128; j++)
				cout << ((OTExtensionBristolROutput*)output.get())->receiverOutputMatrix.squares[0].get_bit(i,j);

			cout << " "<<endl;
		}



    }


    cout<<"Done running"<<endl;


    return 0;
}
#endif
