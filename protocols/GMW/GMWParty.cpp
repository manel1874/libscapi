//
// Created by moriya on 08/01/17.
//

#include "GMWParty.h"

GMWParty::GMWParty(int id, const shared_ptr<Circuit> & circuit, const vector<shared_ptr<ProtocolPartyData>> & parties, int numThreads, string inputFileName) :
        id(id), circuit(circuit), parties(parties), inputFileName(inputFileName) {
    if (parties.size() <= numThreads){
        this->numThreads = parties.size();
        numPartiesForEachThread = 1;
    } else{
        this->numThreads = numThreads;
        numPartiesForEachThread = (parties.size() + numThreads - 1)/ numThreads;
    }
}

void GMWParty::run(){
    auto start = chrono::high_resolution_clock::now();
    generateTriples();
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> generateTotalTime = end - start;
    cout<<"Offline time: "<<generateTotalTime.count() <<endl;

    start = chrono::high_resolution_clock::now();
    inputSharing();
    auto output = computeCircuit();

    end = chrono::high_resolution_clock::now();
    generateTotalTime = end - start;
    cout<<"online time: "<<generateTotalTime.count() <<endl;

    cout << "circuit output:" << endl;
    for (int i = 0; i < output.size(); i++) {
        cout << (int) output[i] << " ";
    }
    cout << endl;

}

void GMWParty::generateTriples(){

    /*
     * Generates a multiplication triple (a0 ^ a1)(b0 ^ b1) = (c0 ^ c1) for each and gate for each party.
     * This is done by comouting 2 random OTs between each pair of parties.
     */

    //There are 4 values for each multiplication triple (a, b, u, v)
    //There is a multiplication triple for each party and for each AND gate.
    int size = parties.size()*circuit->getNrOfAndGates();
    aArray.resize(size);
    bArray.resize(size);
    cArray.resize(size);
    vector<byte> sigma(circuit->getNrOfAndGates());
    vector<byte> x0, x1, xSigma;
    int position;
    byte v, u;

    shared_ptr<OTBatchSOutput> sOutput;
    shared_ptr<OTBatchROutput> rOutput;
    PrgFromOpenSSLAES prg;
    auto key =prg.generateKey(128);
    prg.setKey(key);

    vector<thread> threads(numThreads);
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::generateTriplesForParty, this, ref(prg), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::generateTriplesForParty, this, ref(prg), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
    /*for (int i=0; i < parties.size(); i++) {
        //cout<<"triple with party number "<<parties[i]->getID()<<":"<<endl;

        prg.getPRGBytes(sigma, 0, sigma.size());
        for (int i = 0; i < sigma.size(); i++) {
            sigma[i] = sigma[i] % 2; //sigma should be 0/1
        }

        //If this id is lower than the other id, run the sender role in the OT,
        //else, run the receiver role.
        if (id < parties[i]->getID()) {

            //Play the sender role of the OT and then the receiver role.
            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = parties[i]->getSender()->transfer(&sInput);

            OTExtensionRandomizedRInput rInput(sigma, 8);
            rOutput = parties[i]->getReceiver()->transfer(&rInput);

        } else {
            //Play the receiver role in the OT and then the sender role.
            OTExtensionRandomizedRInput input(sigma, 8);
            rOutput = parties[i]->getReceiver()->transfer(&input);

            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = parties[i]->getSender()->transfer(&sInput);
        }

        /* The sender output of the random ot are x0, x1.
         * Set b = x0 ^ x1
         *     v = x0
         * The receiver output of the random ot is u = Xa.
         *
         *//*
        x0 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR0Arr();
        x1 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR1Arr();
        xSigma = ((OTExtensionBristolROutput *) rOutput.get())->getXSigma();

        position = i * circuit->getNrOfAndGates();
        for (int j = 0; j < circuit->getNrOfAndGates(); j++) {
            //convert the output of the random ot to 0/1.
            x0[j] %= 2;
            x1[j] %= 2;
            xSigma[j] %= 2;

            v = x0[j];                          // v
            bArray[position + j] = v ^ x1[j];   // b
            aArray[position + j] = sigma[j];    // a
            u = xSigma[j];                      // u
            cArray[position + j] = (aArray[position + j] * bArray[position + j]) ^ v ^ u; // c = (ab) ^ u ^ v.

            /*cout << "b = " << (int) bArray[position + j] << endl;
            cout << "v = " << (int) v << endl;
            cout << "a = " << (int) aArray[position + j] << endl;
            cout << "u = " << (int) u << endl;
            cout << "c = " << (int) cArray[position + j] << endl;*/
     /*   }
    }*/
}

void GMWParty::generateTriplesForParty(PrgFromOpenSSLAES & prg, int first, int last){

    vector<byte> sigma(circuit->getNrOfAndGates());
    vector<byte> x0, x1, xSigma;
    int position;
    byte v, u;

    shared_ptr<OTBatchSOutput> sOutput;
    shared_ptr<OTBatchROutput> rOutput;

    for (int i=first; i < last; i++) {
        //cout<<"triple with party number "<<parties[i]->getID()<<":"<<endl;
        mtx.lock();
        prg.getPRGBytes(sigma, 0, sigma.size());
        mtx.unlock();
        for (int i = 0; i < sigma.size(); i++) {
            sigma[i] = sigma[i] % 2; //sigma should be 0/1
        }

        //If this id is lower than the other id, run the sender role in the OT,
        //else, run the receiver role.
        if (id < parties[i]->getID()) {

            //Play the sender role of the OT and then the receiver role.
            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = parties[i]->getSender()->transfer(&sInput);

            OTExtensionRandomizedRInput rInput(sigma, 8);
            rOutput = parties[i]->getReceiver()->transfer(&rInput);

        } else {
            //Play the receiver role in the OT and then the sender role.
            OTExtensionRandomizedRInput input(sigma, 8);
            rOutput = parties[i]->getReceiver()->transfer(&input);

            OTExtensionRandomizedSInput sInput(circuit->getNrOfAndGates(), 8);
            sOutput = parties[i]->getSender()->transfer(&sInput);
        }

        /* The sender output of the random ot are x0, x1.
         * Set b = x0 ^ x1
         *     v = x0
         * The receiver output of the random ot is u = Xa.
         *
         */
        x0 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR0Arr();
        x1 = ((OTExtensionBristolRandomizedSOutput *) sOutput.get())->getR1Arr();
        xSigma = ((OTExtensionBristolROutput *) rOutput.get())->getXSigma();

        position = i * circuit->getNrOfAndGates();
        for (int j = 0; j < circuit->getNrOfAndGates(); j++) {
            //convert the output of the random ot to 0/1.
            x0[j] %= 2;
            x1[j] %= 2;
            xSigma[j] %= 2;

            v = x0[j];                          // v
            bArray[position + j] = v ^ x1[j];   // b
            aArray[position + j] = sigma[j];    // a
            u = xSigma[j];                      // u
            cArray[position + j] = (aArray[position + j] * bArray[position + j]) ^ v ^ u; // c = (ab) ^ u ^ v.
            /*cout<<"gate "<<j<<endl;
            cout << "b = " << (int) bArray[position + j] << endl;
            cout << "v = " << (int) v << endl;
            cout << "a = " << (int) aArray[position + j] << endl;
            cout << "u = " << (int) u << endl;
            cout << "c = " << (int) cArray[position + j] << endl;*/
        }
    }
}
void GMWParty::inputSharing(){
    vector<int> myInputWires = circuit->getPartyInputs(id); //indices of my input wires
    //vector<int> otherInputWires; //indeices of the other party's input wires
    int inputSize = myInputWires.size();
    vector<byte> myInputBits(inputSize, 0); //input bits, will be adjusted to my input shares
   // vector<byte> myShares(inputSize, 0); //the shares to send to the other parties
    //vector<byte> otherShares(inputSize, 0); //the shares to receive from the other parties
    wiresValues.resize(circuit->getNrOfInput(), 0); //all shares of input wires

    PrgFromOpenSSLAES prg;
    auto key =prg.generateKey(128);
    prg.setKey(key);

    //read my input from the input file
    readInputs(myInputBits);

    vector<thread> threads(numThreads);
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::sendSharesToParties, this, ref(prg), ref(myInputBits), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::sendSharesToParties, this, ref(prg), ref(myInputBits), t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
    /*for (int i=0; i < parties.size(); i++) {
        //sample random values to be the shares of the other party.
        prg.getPRGBytes(myShares, 0, inputSize);
        //convert each value to 0/1 and adjust my shares with the sampled values.
        for (int j=0; j<inputSize; j++){
            myShares[j] %= 2;
            myInputBits[j] ^= myShares[j];
            //myInputBits[j] %= 2;
        }


        if (id < parties[i]->getID()) {
            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, wiresValues, i);

        } else{
            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, wiresValues, i);

            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

        }
    }*/

    //Set my input shares in the big shares array
    for (int j=0; j<myInputBits.size(); j++){
        wiresValues[myInputWires[j]] = myInputBits[j];
    }

    /*cout<<"input shares: "<<endl;
    for (int i=0; i<circuit->getNrOfInput(); i++){
        cout<<(int)wiresValues[i]<<endl;
    }*/
}

void GMWParty::sendSharesToParties(PrgFromOpenSSLAES & prg, vector<byte> & myInputBits, int first, int last){

    int inputSize = myInputBits.size();
    vector<byte> myShares(inputSize, 0); //the shares to send to the other parties
    vector<byte> otherShares(inputSize, 0); //the shares to receive from the other parties
    vector<int> otherInputWires; //indeices of the other party's input wires

    for (int i=first; i < last; i++) {
        //sample random values to be the shares of the other party.
        mtx.lock();
        prg.getPRGBytes(myShares, 0, inputSize);
        mtx.unlock();
        //convert each value to 0/1 and adjust my shares with the sampled values.
        for (int j=0; j<inputSize; j++){
            myShares[j] %= 2;
            mtx.lock();
            myInputBits[j] ^= myShares[j];
            mtx.unlock();
        }


        if (id < parties[i]->getID()) {
            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, i);

        } else{
            //receive shares from the other party and set them in the shares array
            receiveShares(otherInputWires, otherShares, i);

            //send shares to my input bits
            parties[i]->getChannel()->write(myShares.data(), myShares.size());

        }
    }
}
void GMWParty::receiveShares(vector<int> & otherInputWires, vector<byte> & otherShares, int i)  {
    //Receive shares from other party
    otherInputWires = circuit->getPartyInputs(parties[i]->getID());
    otherShares.resize(otherInputWires.size(), 0);
    parties[i]->getChannel()->read(otherShares.data(), otherShares.size());

    //Set the given shares in the big shares array.
    for (int j=0; j<otherShares.size(); j++){
        wiresValues[otherInputWires[j]] = otherShares[j];
    }
}

void GMWParty::readInputs(vector<byte> & inputs) const {
    //Read the input from the given input file
    ifstream myfile;
    int input;

    myfile.open(inputFileName);
   for (int i = 0; i<inputs.size(); i++){
        myfile >> input;
        inputs[i] = (byte)input;
    }
    myfile.close();
}

vector<byte> GMWParty::computeCircuit(){
    Gate gate;
    wiresValues.resize(circuit->getNrOfInput() + circuit->getNrOfGates(), 0);
    vector<bool> isWireReady(circuit->getNrOfInput() + circuit->getNrOfGates(), false);

    for (int i=0; i<circuit->getNrOfInput(); i++){
        isWireReady[i] = true;
    }

    int andGatesCounter = 0, firstAndGateToRecompute = -1, numAndGatesComputed = 0, andGatesComputedCounter;
    vector<vector<byte>> myD(parties.size()), myE(parties.size());

    byte x, y, a, b;

    for (int i=0; i<circuit->getNrOfGates(); i++){
        //cout<<i<<endl;
        gate = circuit->getGates()[i];

        //In case the gate is not ready, meaning that at least one of its input wires wasn't computed yet,
        //We should run the ot in order to compute all gates till here.
        //After the ot, the input wire will be ready.
        if (!isWireReady[gate.inputIndex1] || ((gate.inFan != 1) && !isWireReady[gate.inputIndex2])) {
            //cout<<"input 1 = "<<gate.inputIndex1<<endl;
           // cout<<"input 2 = "<<gate.inputIndex2<<endl;
             //recomputeAndGates(recomputeGate, firstAndGateToRecompute, myD, myE, otherD, otherE, d, e, z, index, i,
             //                      isWireReady, numAndGatesComputed, 0, parties.size());
            recomputeAndGatesWithThreads(firstAndGateToRecompute, myD, myE, i, isWireReady, numAndGatesComputed, andGatesComputedCounter);

            for (int j=0; j<parties.size(); j++){
                myD[j].clear();
                myE[j].clear();
            }

            numAndGatesComputed += andGatesComputedCounter;
            //cout<<"numAndGatesComputed = "<<numAndGatesComputed<<endl;
            //recomputeAndGates(recomputeGate, firstAndGateToRecompute, myD, myE, otherD, otherE, d, e, z, index, i, isWireReady, numAndGatesComputed);
            firstAndGateToRecompute = -1;
        }
        //The gate is ready to be computed, so continue computing:
        // xor gate
        if (gate.gateType == 6) {
             //in case of xor gate the output share is the xor of the input shares
            wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1] ^ wiresValues[gate.inputIndex2];
            isWireReady[gate.outputIndex] = true;
            //cout<<"wiresValues["<<gate.outputIndex<<"] = "<< (int)wiresValues[gate.outputIndex]<<endl;
        //not gate
        } else if (gate.gateType == 12){
            if (id == 0) {
                //in case of xor gate the output share is the xor of the input shares
                wiresValues[gate.outputIndex] = 1 - wiresValues[gate.inputIndex1];
            } else {
                wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1];
            }
            isWireReady[gate.outputIndex] = true;
            //cout<<"wiresValues["<<gate.outputIndex<<"] = "<< (int)wiresValues[gate.outputIndex]<<endl;
        //and/or gate
        } else if (gate.gateType == 1 || gate.gateType == 7) {
            if (firstAndGateToRecompute == -1)
                firstAndGateToRecompute = i;

            //In case of or gate, (a | b) = ~(~a^~b).
            //not gate can be computed by p0 change its bit.
            // So, in order to compute or p0 first change its input bit, than compute and gate and then p0 again change the output bit.
            if (gate.gateType == 7 && id == 0) {
                // cout<<"in or gate. flip input values before and"<<endl;
                wiresValues[gate.inputIndex1] = 1 - wiresValues[gate.inputIndex1];
                wiresValues[gate.inputIndex2] = 1 - wiresValues[gate.inputIndex2];
            }

            //The output share of the and gate is calculated by x1^y1 + x1y2 + x1y3 + ...
            //If the number of parties is odd, the calculation of x*y is done by the multiplication triples computation.
            // If the number is even, the value of x*y is reset so it should be computed again:
            if (parties.size() % 2 == 0) {
                wiresValues[gate.outputIndex] = wiresValues[gate.inputIndex1] * wiresValues[gate.inputIndex2];
                //cout << "wiresValues[" << gate.outputIndex << "] = " << (int) wiresValues[gate.outputIndex] << endl;
            }

            //Compute other multiplication values
            //for all parties, prepare arrays to hold d, e, values.
            //These values will be sent to the other party
            for (int j=0; j<parties.size(); j++){
//cout<<"party "<<parties[j]->getID()<<endl;
                //Calculate d = x^a, e = y^b
                x  = wiresValues[gate.inputIndex1];
                a = aArray[j * circuit->getNrOfAndGates() + andGatesCounter];
                y = wiresValues[gate.inputIndex2];
                b = bArray[j * circuit->getNrOfAndGates() + andGatesCounter];
                myD[j].push_back(x ^ a);
                myE[j].push_back(y ^ b);
            }
            andGatesCounter++;

            //Flip again the input bit in order to remain true for other gates.
            if (gate.gateType == 7 && id == 0){
                //cout<<"in or gate. flip input values avter and"<<endl;
                wiresValues[gate.inputIndex1] = 1 - wiresValues[gate.inputIndex1];
                wiresValues[gate.inputIndex2] = 1 - wiresValues[gate.inputIndex2];
            }
        }

    }

    //Recompute the last and gates
    if (firstAndGateToRecompute != -1){
        //recomputeAndGates(recomputeGate, firstAndGateToRecompute, myD, myE, otherD, otherE, d, e, z, index, circuit->getNrOfGates(), isWireReady, numAndGatesComputed, 0, parties.size());
        recomputeAndGatesWithThreads(firstAndGateToRecompute, myD, myE, circuit->getNrOfGates(), isWireReady, numAndGatesComputed, numAndGatesComputed);
    }

    //after computing the circuit, calculate the output values by receiving the shares;
    return revealOutput();
}

void GMWParty::recomputeAndGatesWithThreads(int & firstAndGateToRecompute, const vector<vector<byte>> & myD, const vector<vector<byte>> & myE, int i,
                                            vector<bool> & isWireReady, int & numAndGatesComputed, int & andGatesComputedCounter){
    vector<thread> threads(numThreads);
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::recomputeAndGates, this, ref(firstAndGateToRecompute), ref(myD),
                                ref(myE), i, ref(isWireReady), numAndGatesComputed, ref(andGatesComputedCounter),
                                t * numPartiesForEachThread, (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::recomputeAndGates, this, ref(firstAndGateToRecompute), ref(myD),
                                ref(myE), i, ref(isWireReady), numAndGatesComputed, ref(andGatesComputedCounter),
                                t * numPartiesForEachThread, parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
}


void GMWParty::recomputeAndGates(int firstAndGateToRecompute, const vector<vector<byte>> & myD, const vector<vector<byte>> & myE, int i,
                                 vector<bool> & isWireReady, int numAndGatesComputed, int & andGatesComputedCounter, int first, int last) {
    Gate recomputeGate;
    byte d, e, z;
    int index;
    vector<byte> otherD, otherE;

    int recomputeAndGatesCounter;
    for (int j=first; j < last; j++){
        otherD.resize(myD[j].size());
        otherE.resize(myE[j].size());
        //The party with the lower id will send its bytes first
        if (id < parties[j]->getID()) {
            //cout<<"sender. should send to party "<<parties[j]->getID()<<endl;
            //send my d ,e
            parties[j]->getChannel()->write(myD[j].data(), myD[j].size());
            parties[j]->getChannel()->write(myE[j].data(), myE[j].size());
            //cout<<"receiver. should receive from party "<<parties[j]->getID()<<endl;
            //receive other d, e
            parties[j]->getChannel()->read(otherD.data(), otherD.size());
            parties[j]->getChannel()->read(otherE.data(), otherE.size());
        } else {
            //cout<<"receiver. should receive from party "<<parties[j]->getID()<<endl;
            //receive other d, e
            parties[j]->getChannel()->read(otherD.data(), otherD.size());
            parties[j]->getChannel()->read(otherE.data(), otherE.size());
            //cout<<"sender. should send to party "<<parties[j]->getID()<<endl;
            //send my d ,e
            parties[j]->getChannel()->write(myD[j].data(), myD[j].size());
            parties[j]->getChannel()->write(myE[j].data(), myE[j].size());
        }

        //Go on each and gate in the ot and compute its output share.
        recomputeAndGatesCounter = 0;
        for (int k=firstAndGateToRecompute; k < i; k++){

            recomputeGate = circuit->getGates()[k];

            if (recomputeGate.gateType == 1 || recomputeGate.gateType == 7) {

                //d = d1^d2
                d = myD[j][recomputeAndGatesCounter] ^ otherD[recomputeAndGatesCounter];
                //e = e1^e2
                e = myE[j][recomputeAndGatesCounter] ^ otherE[recomputeAndGatesCounter];
                //z = db ^ ea ^c ^ de
                index = j * circuit->getNrOfAndGates() + numAndGatesComputed + recomputeAndGatesCounter;
                z = d * bArray[index];
                z = z ^ (e * aArray[index]);
                z = z ^ cArray[index];
                if (id < parties[j]->getID()) {
                    z = z ^ (d * e);
                }
                mtx.lock();
                wiresValues[recomputeGate.outputIndex] ^= z;
                isWireReady[recomputeGate.outputIndex] = true;
                mtx.unlock();
                recomputeAndGatesCounter++;
                //cout<<"wiresValues["<<recomputeGate.outputIndex<<"] = "<< (int)wiresValues[recomputeGate.outputIndex]<<endl;
            }

            if (recomputeGate.gateType == 7 && id == 0 && j==(last - 1)){
                mtx.lock();
                wiresValues[recomputeGate.outputIndex] = 1 - wiresValues[recomputeGate.outputIndex];
                mtx.unlock();
            }
        }
    }
    mtx.lock();
    andGatesComputedCounter = recomputeAndGatesCounter;
    mtx.unlock();
}
/*
void GMWParty::recomputeAndGates(Gate &recomputeGate, int firstAndGateToRecompute, vector<vector<byte>> &myD,
                                 vector<vector<byte>> &myE, vector<byte> &otherD, vector<byte> &otherE, byte d,
                                 byte e, byte z, int index, int i, vector<bool> & isWireReady, int & numAndGatesComputed, int first, int last) {
    int recomputeAndGatesCounter;
    for (int j=first; j < last; j++){
            otherD.resize(myD[j].size());
            otherE.resize(myE[j].size());
            //The party with the lower id will send its bytes first
            if (id < parties[j]->getID()) {
                //send my d ,e
                parties[j]->getChannel()->write(myD[j].data(), myD[j].size());
                parties[j]->getChannel()->write(myE[j].data(), myE[j].size());

                //receive other d, e
                parties[j]->getChannel()->read(otherD.data(), otherD.size());
                parties[j]->getChannel()->read(otherE.data(), otherE.size());
            } else {
                //receive other d, e
                parties[j]->getChannel()->read(otherD.data(), otherD.size());
                parties[j]->getChannel()->read(otherE.data(), otherE.size());

                //send my d ,e
                parties[j]->getChannel()->write(myD[j].data(), myD[j].size());
                parties[j]->getChannel()->write(myE[j].data(), myE[j].size());
            }

            //Go on each and gate in the ot and compute its output share.
            recomputeAndGatesCounter = 0;
            for (int k=firstAndGateToRecompute; k < i; k++){
                recomputeGate = circuit->getGates()[k];

                if (recomputeGate.gateType == 2 || recomputeGate.gateType == 3) {

                    //d = d1^d2
                    d = myD[j][recomputeAndGatesCounter] ^ otherD[recomputeAndGatesCounter];
                    //e = e1^e2
                    e = myE[j][recomputeAndGatesCounter] ^ otherE[recomputeAndGatesCounter];
                    //z = db ^ ea ^c ^ de
                    index = j * circuit->getNrOfAndGates() + numAndGatesComputed + recomputeAndGatesCounter;
                    z = d * bArray[index];
                    z = z ^ (e * aArray[index]);
                    z = z ^ cArray[index];
                    if (id < parties[j]->getID()) {
                        z = z ^ (d * e);
                    }
                    wiresValues[recomputeGate.outputIndex] ^= z;
                    //wiresValues[recomputeGate.outputIndex] %= 2;
                    isWireReady[recomputeGate.outputIndex] = true;
                    recomputeAndGatesCounter++;

                    //cout<<"wiresValues["<<recomputeGate.outputIndex<<"] = "<< (int)wiresValues[recomputeGate.outputIndex]<<endl;
                }

                if (recomputeGate.gateType == 3 && id == 0 && j==(last - 1)){
                    cout<<"in or gate. flip output value after and"<<endl;
                    wiresValues[recomputeGate.outputIndex] = 1 - wiresValues[recomputeGate.outputIndex];
                }
            }
            myD[j].clear();
            myE[j].clear();
        }
    numAndGatesComputed += recomputeAndGatesCounter;
}*/

vector<byte> GMWParty::revealOutput() {
    vector<int> myOutputIndices = circuit->getPartyOutputs(id);
    int myOutputSize = myOutputIndices.size();
    vector<byte> output(myOutputSize);
    for (int i=0; i<myOutputSize; i++){
        output[i] = wiresValues[myOutputIndices[i]];
    }
    vector<thread> threads(numThreads);
    //send output shares to each party that needs it
    for (int t=0; t<numThreads; t++) {
        if ((t + 1) * numPartiesForEachThread <= parties.size()) {
            threads[t] = thread(&GMWParty::revealOutputFromParty, this, ref(output), t * numPartiesForEachThread,
                                (t + 1) * numPartiesForEachThread);
        } else {
            threads[t] = thread(&GMWParty::revealOutputFromParty, this, ref(output), t * numPartiesForEachThread,
                                parties.size());
        }
    }
    for (int t=0; t<numThreads; t++){
        threads[t].join();
    }
    return output;
}

void GMWParty::revealOutputFromParty(vector<byte> & output, int first, int last){
    vector<int> otherOutputsIndices;
    vector<byte> otherOutputstoSend;
    vector<byte> otherOutputstoReceive(output.size());

    for (int i=first; i < last; i++){
        otherOutputsIndices = circuit->getPartyOutputs(parties[i]->getID());
        otherOutputstoSend.resize(otherOutputsIndices.size());

        for (int j=0; j<otherOutputsIndices.size(); j++){
            otherOutputstoSend[j] = wiresValues[otherOutputsIndices[j]];
        }
        if (id < parties[i]->getID()) {
            parties[i]->getChannel()->write(otherOutputstoSend.data(), otherOutputstoSend.size());

            parties[i]->getChannel()->read(otherOutputstoReceive.data(), otherOutputstoReceive.size());
        } else{
            parties[i]->getChannel()->read(otherOutputstoReceive.data(), otherOutputstoReceive.size());

            parties[i]->getChannel()->write(otherOutputstoSend.data(), otherOutputstoSend.size());

        }
        mtx.lock();
        for (int j=0; j<output.size() ; j++){
            output[j] ^= otherOutputstoReceive[j];
        }
        mtx.unlock();

    }
}