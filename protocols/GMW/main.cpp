#include <iostream>
#include "Circuit.h"
#include "MPCCommunication.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {

    shared_ptr<Circuit> circuit = make_shared<Circuit>();
    circuit->readCircuit(argv[2]);

    int id = atoi(argv[1]);

    string tmp = "init times";
    byte tmpBytes[20];
    int numThreads = atoi(argv[5]);

    int allOnlineTimes = 0;
    int allOfflineTimes = 0;
    chrono::high_resolution_clock::time_point start, end;
    int generateTotalTime;
    vector<byte> output;
    //cout << "num of threads : " << numThreads << endl;
    GMWParty party(id, circuit, argv[3], numThreads, argv[4]);
    auto parties = party.getParties();
    for (int i=0; i<10; i++) {

        //cout << "parties size : " << parties.size() << endl;
        for (int i = 0; i < parties.size(); i++) {
            if (parties[i]->getID() < id) {
                parties[i]->getChannel()->write(tmp);
                parties[i]->getChannel()->read(tmpBytes, tmp.size());
            } else {
                parties[i]->getChannel()->read(tmpBytes, tmp.size());
                parties[i]->getChannel()->write(tmp);
            }
        }


        //cout << "----------start protocl--------------" << endl;
        //party.run();

        //cout << "----------finish protocl--------------" << endl;

        //offline phase
        start = chrono::high_resolution_clock::now();
        party.runOffline();
        end = chrono::high_resolution_clock::now();
        generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        allOfflineTimes += generateTotalTime;
        //cout<<"Offline time: "<<generateTotalTime <<" milliseconds"<<endl;


        //Online phase
        start = chrono::high_resolution_clock::now();
        output = party.runOnline();
        end = chrono::high_resolution_clock::now();
        generateTotalTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        allOnlineTimes += generateTotalTime;
        //cout<<"online time: "<<generateTotalTime <<" milliseconds"<<endl;
    }
    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++) {
        cout << (int) output[i] << " ";
    }
    cout << endl;
    cout<<"average offline time = "<<allOfflineTimes/10<<endl;
    cout<<"average online time = "<<allOnlineTimes/10<<endl;
    return 0;
}

