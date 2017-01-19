//
// Created by moriya on 04/01/17.
//

#ifndef GMW_GMWPARTY_H
#define GMW_GMWPARTY_H

#include "Circuit.h"
#include "MPCCommunication.h"
#include "../../include/primitives/Prg.hpp"
#include "../../include/CryptoInfra/Protocol.hpp"
#include "../../include/CryptoInfra/SecurityLevel.hpp"
#include <thread>
#include <mutex>

class GMWParty : public Protocol, public SemiHonest{

private:
    int id, numThreads, numPartiesForEachThread;
    shared_ptr<Circuit> circuit;
    vector<shared_ptr<ProtocolPartyData>> parties;
    vector<byte> aArray, bArray, cArray;
    vector<byte> wiresValues;
    mutex mtx;
    string inputFileName;

    void generateTriples();

    void inputSharing();

    vector<byte> computeCircuit();

    void readInputs(vector<byte> & inputs) const;

    void generateTriplesForParty(PrgFromOpenSSLAES & prg, int first, int last);

    void sendSharesToParties(PrgFromOpenSSLAES & prg, vector<byte> & myInputBits, int first, int last);

    void receiveShares(vector<int> &otherInputWires, vector<byte> &otherShares, int i);

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

    GMWParty(int id, const shared_ptr<Circuit> & circuit, const vector<shared_ptr<ProtocolPartyData>> & parties, int numThreads, string inputFileName);

    /*
     * Implement the function derived from the Protocol abstract class.
     */
    void run() override;


};
#endif //GMW_GMWPARTY_H
