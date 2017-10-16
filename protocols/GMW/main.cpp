#include <iostream>
#include "Circuit.h"
#include "MPCCommunication.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {


    string tmp = "init times";
    byte tmpBytes[20];

    int allOnlineTimes = 0;
    int allOfflineTimes = 0;
    chrono::high_resolution_clock::time_point start, end;
    int generateTotalTime;
    vector<byte> output;
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


    //offline phase
    start = chrono::high_resolution_clock::now();
    party.runOffline();
    end = chrono::high_resolution_clock::now();
    generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    allOfflineTimes += generateTotalTime;
    party.readInputs();

    //Online phase
    start = chrono::high_resolution_clock::now();
    party.runOnline();
    output = party.getOutput();
    end = chrono::high_resolution_clock::now();
    generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    allOnlineTimes += generateTotalTime;

    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++)
    {
        cout << (int) output[i] << " ";
    }

    cout << endl;

    cout<<"average offline time = "<<allOfflineTimes/10<<endl;
    cout<<"average online time = "<<allOnlineTimes/10<<endl;
    return 0;
}

