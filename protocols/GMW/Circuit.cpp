//
// Created by moriya on 04/01/17.
//

#include "Circuit.h"

void Circuit::readCircuit(const char* fileName)
{
cout<<fileName<<endl;
    int input1, input2, output, type, numOfinputsForParty, numOfoutputsForParty;
    int numberOfGates, numberOfOutputs, currentPartyNumber;
    int gateIndex = 0;
    ifstream myfile;

    myfile.open(fileName);

    if (myfile.is_open())
    {

        myfile >> numberOfGates;//get the gates
        myfile >> numberOfParties;

        //inputs
        vector<int> numOfInputsForEachParty(numberOfParties);
        partiesInputs.resize(numberOfParties);

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;
            myfile >> numOfinputsForParty;

            numOfInputsForEachParty[currentPartyNumber - 1] = numOfinputsForParty;

            partiesInputs[currentPartyNumber - 1].resize(numOfInputsForEachParty[currentPartyNumber - 1]);

            for (int i = 0; i<numOfInputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesInputs[currentPartyNumber - 1][i];
            }
        }

        //outputs
        vector<int> numOfOutputsForEachParty(numberOfParties);
        partiesOutputs.resize(numberOfParties);

        for (int j = 0; j<numberOfParties; j++) {
            myfile >> currentPartyNumber;

            myfile >> numOfoutputsForParty;
            numOfOutputsForEachParty[currentPartyNumber - 1] = numOfoutputsForParty;
            partiesOutputs[currentPartyNumber - 1].resize(numOfOutputsForEachParty[currentPartyNumber - 1]);

            for (int i = 0; i<numOfOutputsForEachParty[currentPartyNumber - 1]; i++) {
                myfile >> partiesOutputs[currentPartyNumber - 1][i];
            }
        }

        //calculate the total number of inputs and outputs
        for (int i = 0; i<numberOfParties; i++) {
            nrOfInput += numOfInputsForEachParty[i];
            nrOfOutput += numOfOutputsForEachParty[i];
        }

        //allocate memory for the gates, We add one gate for the all-one gate whose output is always 1 and thus have a wire who is always 1 without the
        //involvement of the user. This will be useful to turn a NOT gate into a XORGate
        //gates.resize(numberOfGates + nrOfInputGates + nrOfOutputGates);
        gates.resize(numberOfGates);
        //   gates.resize(20);

        //create the input gates

        //create the input gates for each party
        /*for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfInputsForEachParty[i];j++) {

                gates[gateIndex].gateType = 0;
                gates[gateIndex].inputIndex1 = -1;//irrelevant
                gates[gateIndex].inputIndex2 = -1;//irrelevant
                gates[gateIndex].outputIndex = partiesInputs[i][j];//the wire index

                gateIndex++;

            }
        }*/

        //go over the file and create gate by gate
        for (int i = 0; i<numberOfGates; i++)
        {

            //get  each row that represents a gate
            myfile >> input1;
            myfile >> input2;
            myfile >> output;
            myfile >> type;

            gates[i].inputIndex1 = input1;
            gates[i].inputIndex2 = input2;
            gates[i].outputIndex = output;
            gates[i].gateType = type;

            if (type == 1) {
                nrOfXorGates++;
            }
            else if (type = 2) {
                nrOfAndGates++;
            }

        }

        cout<<"num of and gates = "<<nrOfAndGates<<endl;
        cout<<"num of xor gates = "<<nrOfXorGates<<endl;

        //gateIndex = numberOfGates + nrOfInputGates;
        //create the output gates for each party
        /*for (int i = 0; i < numberOfParties; i++) {

            for (int j = 0; j < numOfOutputsForEachParty[i]; j++) {

                gates[gateIndex].gateType = 3;
                gates[gateIndex].input1 = partiesOutputs[i][j];
                gates[gateIndex].input2 = 0;//irrelevant
                gates[gateIndex].output = 0;//irrelevant
                gates[gateIndex].party = i + 1;

                gateIndex++;

            }
        }*/

    }
    myfile.close();
}