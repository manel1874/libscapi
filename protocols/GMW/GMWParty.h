//
// Created by moriya on 04/01/17.
//

#ifndef GMW_GMWPARTY_H
#define GMW_GMWPARTY_H

#include "Circuit.h"
#include "MPCCommunication.h"
#include <libscapi/include/primitives/Prg.hpp>
#include <thread>
#include <mutex>

class GMWParty{

private:
    int id, numThreads, numPartiesForEachThread;
    shared_ptr<Circuit> circuit;
    vector<shared_ptr<ProtocolPartyData>> parties;
    vector<byte> aArray, bArray, cArray;
    vector<byte> wiresValues;
    void readInputs(string inputsFile, vector<byte> & inputs) const;
    mutex mtx;

    void generateTriplesForParty(PrgFromOpenSSLAES & prg, int first, int last);

    void sendSharesToParties(PrgFromOpenSSLAES & prg, vector<byte> & myInputBits, int first, int last);

    void receiveShares(vector<int> &otherInputWires, vector<byte> &otherShares, vector<byte> &inputShares, int i) const;

    //void recomputeAndGates(Gate &recomputeGate, int firstAndGateToRecompute, vector<vector<byte>> &myD,
    //                       vector<vector<byte>> &myE, vector<byte> &otherD, vector<byte> &otherE, byte d, byte e,
     //                   byte z, int index, int i, vector<bool> & isWireReady, int & numAndGatesComputed, int first, int last);

    void recomputeAndGatesWithThreads(int & firstAndGateToRecompute, const vector<vector<byte>> & myD,
                                      const vector<vector<byte>> & myE, int i, vector<bool> & isWireReady,
                                      int & numAndGatesComputed, int & andGatesComputedCounter);

    void recomputeAndGates(int firstAndGateToRecompute, const vector<vector<byte>> & myD, const vector<vector<byte>> & myE, int i,
                           vector<bool> & isWireReady, int numAndGatesComputed, int & andGatesComputedCounter, int first, int last);

    vector<byte> revealOutput();

    void revealOutputFromParty(vector<byte> & output, int first, int last);

public:

    GMWParty(int id, const shared_ptr<Circuit> & circuit, const vector<shared_ptr<ProtocolPartyData>> & parties, int numThreads);

    void GenerateTriples();

    void inputSharing(string inputsFile);

    vector<byte> computeCircuit();
};
#endif //GMW_GMWPARTY_H
