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
        OTSemiHonestExtensionSender sender("localhost", 7000);
        sender.transfer(nOTs);


    }
    else {
        cout<<"nOTS: "<< nOTs<<endl;
        OTSemiHonestExtensionReciever reciever("localhost", 7000);


        reciever.transfer(nOTs, receiverInput);

    }


    cout<<"Done running"<<endl;


    return 0;
}
