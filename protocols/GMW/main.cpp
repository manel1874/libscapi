#include <iostream>
#include "Circuit.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {


    string tmp = "init times";
    byte tmpBytes[20];


    GMWParty party(argc, argv);

    auto parties = party.getParties();

    for (int i = 0; i < parties.size(); i++) {
        if (parties[i]->getID() < party.getID()) {
            parties[i]->getChannel()->write(tmp);
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
        } else {
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
            parties[i]->getChannel()->write(tmp);
        }
    }

    party.run();
    //offline phase
//    start = chrono::high_resolution_clock::now();
//    party.runOffline();
//    end = chrono::high_resolution_clock::now();
//    generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//    allOfflineTimes += generateTotalTime;
//    party.readInputs();
//
//    //Online phase
//    start = chrono::high_resolution_clock::now();
//    party.runOnline();
    vector<byte> output = party.getOutput();
//    end = chrono::high_resolution_clock::now();
//    generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//    allOnlineTimes += generateTotalTime;

    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++)
    {
        cout << (int) output[i] << " ";
    }

    cout << endl;

//    cout<<"average offline time = "<<allOfflineTimes<<endl;
//    cout<<"average online time = "<<allOnlineTimes<<endl;
    return 0;
}

