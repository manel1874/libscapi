#include <iostream>
#include "Circuit.h"
#include "MPCCommunication.h"
#include "GMWParty.h"

int main(int argc, char* argv[]) {
    boost::asio::io_service io_service;
    shared_ptr<Circuit> circuit = make_shared<Circuit>();
    circuit->readCircuit(argv[2]);

    int id = atoi(argv[1]);
    auto parties = MPCCommunication::setCommunication(io_service, id, circuit->getNrOfParties(), argv[3]);

    string tmp = "init times";
    byte tmpBytes[20];
    for (int i=0; i<parties.size(); i++){
        if (parties[i]->getID() < id){
            parties[i]->getChannel()->write(tmp);
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
        } else {
            parties[i]->getChannel()->read(tmpBytes, tmp.size());
            parties[i]->getChannel()->write(tmp);
        }
    }
    int numThreads = atoi(argv[5]);
    GMWParty party(id, circuit, parties, numThreads);
    auto start = chrono::high_resolution_clock::now();
    party.GenerateTriples();
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> generateTotalTime = end - start;
    cout<<"Offline time: "<<generateTotalTime.count() <<endl;

    start = chrono::high_resolution_clock::now();
    party.inputSharing(argv[4]);
    auto output = party.computeCircuit();

    end = chrono::high_resolution_clock::now();
    generateTotalTime = end - start;
    cout<<"online time: "<<generateTotalTime.count() <<endl;

    cout<<"circuit output:"<<endl;
    for (int i=0; i<output.size(); i++){
        cout<<(int)output[i]<< " ";
    }
    cout<<endl;

    return 0;
}

